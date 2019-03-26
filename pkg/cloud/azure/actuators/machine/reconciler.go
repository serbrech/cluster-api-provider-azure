/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package machine

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-10-01/compute"
	"github.com/pkg/errors"
	apicorev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/apis/azureprovider/v1alpha1"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/cloud/azure"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/cloud/azure/actuators"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/cloud/azure/converters"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/cloud/azure/services/networkinterfaces"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/cloud/azure/services/virtualmachines"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// UserDataSecretKey holds the startup scripts for machines
	UserDataSecretKey = "userData"
	// DefaultBootstrapTokenTTL default ttl for bootstrap token
	DefaultBootstrapTokenTTL = 10 * time.Minute
)

// Reconciler are list of services required by cluster actuator, easy to create a fake
type Reconciler struct {
	scope                *actuators.MachineScope
	networkInterfacesSvc azure.Service
	virtualMachinesSvc   azure.Service
	//virtualMachinesExtSvc azure.Service
}

// NewReconciler populates all the services based on input scope
func NewReconciler(scope *actuators.MachineScope) *Reconciler {
	return &Reconciler{
		scope:                scope,
		networkInterfacesSvc: networkinterfaces.NewService(scope),
		virtualMachinesSvc:   virtualmachines.NewService(scope),
		//virtualMachinesExtSvc: virtualmachineextensions.NewService(scope),
	}
}

// Create creates machine if and only if machine exists, handled by cluster-api
func (s *Reconciler) Create(ctx context.Context) error {
	networkInterfaceSpec := &networkinterfaces.Spec{
		Name:     fmt.Sprintf("%s-nic", s.scope.Machine.Name),
		VNETName: azure.DefaultVnetName,
	}
	switch set := s.scope.Machine.ObjectMeta.Labels["machine.openshift.io/cluster-api-machine-role"]; set {
	case v1alpha1.Node:
		networkInterfaceSpec.SubnetName = azure.DefaultNodeSubnetName
	case v1alpha1.ControlPlane:
		networkInterfaceSpec.SubnetName = azure.DefaultControlPlaneSubnetName
		networkInterfaceSpec.PublicLoadBalancerName = azure.DefaultPublicLBName
		networkInterfaceSpec.InternalLoadBalancerName = azure.DefaultInternalLBName
		networkInterfaceSpec.NatRule = 0
	default:
		return errors.Errorf("Unknown value %s for label `set` on machine %s, skipping machine creation", set, s.scope.Machine.Name)
	}

	netInterface, err := s.networkInterfacesSvc.Get(ctx, networkInterfaceSpec)
	if err != nil && netInterface == nil {
		err = s.networkInterfacesSvc.CreateOrUpdate(ctx, networkInterfaceSpec)
		if err != nil {
			return errors.Wrap(err, "Unable to create VM network interface")
		}
	}

	if err != nil {
		return errors.Wrap(err, "Unable to get VM network interface")
	}

	decoded, err := base64.StdEncoding.DecodeString(s.scope.MachineConfig.SSHPublicKey)
	if err != nil {
		errors.Wrapf(err, "failed to decode ssh public key")
	}

	scriptData := ""
	if s.scope.MachineConfig.UserDataSecret != nil {
		var userDataSecret apicorev1.Secret
		err := s.scope.MachineClient.Get(context.Background(), client.ObjectKey{Namespace: s.scope.Namespace(), Name: s.scope.MachineConfig.UserDataSecret.Name}, &userDataSecret)
		if err != nil {
			return errors.Wrapf(err, "error getting user data secret %s in namespace %s", s.scope.MachineConfig.UserDataSecret.Name, s.scope.Namespace())
		}
		if data, exists := userDataSecret.Data[UserDataSecretKey]; exists {
			scriptData = string(data)
		} else {
			klog.Warningf("Secret %v/%v does not have %s field set. Thus, no user data applied when creating an instance.", s.scope.Namespace(), s.scope.MachineConfig.UserDataSecret.Name, UserDataSecretKey)
		}
	} else {
		return errors.Wrapf(err, "failed to get vm startup script")
	}

	vmSize := "Standard_DS4_v2"
	if s.scope.MachineConfig.VMSize != "" {
		vmSize = s.scope.MachineConfig.VMSize
	}

	vmSpec := &virtualmachines.Spec{
		Name:       s.scope.Machine.Name,
		NICName:    networkInterfaceSpec.Name,
		SSHKeyData: string(decoded),
		Size:       vmSize,
		OSDisk:     s.scope.MachineConfig.OSDisk,
		Image:      s.scope.MachineConfig.Image,
		CustomData: base64.StdEncoding.EncodeToString([]byte(scriptData)),
	}
	err = s.virtualMachinesSvc.CreateOrUpdate(ctx, vmSpec)
	if err != nil {
		return errors.Wrapf(err, "failed to create or get machine")
	}

	// vmExtSpec := &virtualmachineextensions.Spec{
	// 	Name:       "startupScript",
	// 	VMName:     s.scope.Machine.Name,
	// 	ScriptData: scriptData,
	// }
	// err = s.virtualMachinesExtSvc.CreateOrUpdate(ctx, vmExtSpec)
	// if err != nil {
	// 	return errors.Wrapf(err, "failed to create or get machine vm extensions")
	// }

	// TODO: update once machine controllers have a way to indicate a machine has been provisoned. https://github.com/kubernetes-sigs/cluster-api/issues/253
	// Seeing a node cannot be purely relied upon because the provisioned control plane will not be registering with
	// the stack that provisions it.
	if s.scope.Machine.Annotations == nil {
		s.scope.Machine.Annotations = map[string]string{}
	}

	s.scope.Machine.Annotations["cluster-api-provider-azure"] = "true"

	return nil
}

// Update updates machine if and only if machine exists, handled by cluster-api
func (s *Reconciler) Update(ctx context.Context) error {
	vmSpec := &virtualmachines.Spec{
		Name: s.scope.Machine.Name,
	}
	vmInterface, err := s.virtualMachinesSvc.Get(ctx, vmSpec)
	if err != nil {
		return errors.Errorf("failed to get vm: %+v", err)
	}

	vm, ok := vmInterface.(compute.VirtualMachine)
	if !ok {
		return errors.New("returned incorrect vm interface")
	}

	// We can now compare the various Azure state to the state we were passed.
	// We will check immutable state first, in order to fail quickly before
	// moving on to state that we can mutate.
	if isMachineOutdated(s.scope.MachineConfig, converters.SDKToVM(vm)) {
		return errors.Errorf("found attempt to change immutable state")
	}

	// TODO: Uncomment after implementing tagging.
	// Ensure that the tags are correct.
	/*
		_, err = a.ensureTags(computeSvc, machine, scope.MachineStatus.VMID, scope.MachineConfig.AdditionalTags)
		if err != nil {
			return errors.Errorf("failed to ensure tags: %+v", err)
		}
	*/

	return nil
}

// Exists checks if machine exists
func (s *Reconciler) Exists(ctx context.Context) (bool, error) {
	exists, err := s.isVMExists(ctx)
	if err != nil {
		return false, err
	} else if !exists {
		return false, nil
	}

	switch *s.scope.MachineStatus.VMState {
	case v1alpha1.VMStateSucceeded:
		klog.Infof("Machine %v is running", *s.scope.MachineStatus.VMID)
	case v1alpha1.VMStateUpdating:
		klog.Infof("Machine %v is updating", *s.scope.MachineStatus.VMID)
	default:
		return false, nil
	}

	return true, nil
}

// Delete reconciles all the services in pre determined order
func (s *Reconciler) Delete(ctx context.Context) error {
	vmSpec := &virtualmachines.Spec{
		Name: s.scope.Machine.Name,
	}

	err := s.virtualMachinesSvc.Delete(ctx, vmSpec)
	if err != nil {
		return errors.Wrapf(err, "failed to delete machine")
	}

	networkInterfaceSpec := &networkinterfaces.Spec{
		Name:     fmt.Sprintf("%s-nic", s.scope.Machine.Name),
		VNETName: azure.DefaultVnetName,
	}

	err = s.networkInterfacesSvc.Delete(ctx, networkInterfaceSpec)
	if err != nil {
		return errors.Wrapf(err, "Unable to delete network interface")
	}

	return nil
}

// isMachineOutdated checks that no immutable fields have been updated in an
// Update request.
// Returns a bool indicating if an attempt to change immutable state occurred.
//  - true:  An attempt to change immutable state occurred.
//  - false: Immutable state was untouched.
func isMachineOutdated(machineSpec *v1alpha1.AzureMachineProviderSpec, vm *v1alpha1.VM) bool {
	// VM Size
	if machineSpec.VMSize != vm.VMSize {
		return true
	}

	// TODO: Add additional checks for immutable fields

	// No immutable state changes found.
	return false
}

func (s *Reconciler) isVMExists(ctx context.Context) (bool, error) {
	vmSpec := &virtualmachines.Spec{
		Name: s.scope.Name(),
	}
	vmInterface, err := s.virtualMachinesSvc.Get(ctx, vmSpec)

	if err != nil && vmInterface == nil {
		return false, nil
	}

	if err != nil {
		return false, errors.Wrap(err, "Failed to get vm")
	}

	vm, ok := vmInterface.(compute.VirtualMachine)
	if !ok {
		return false, errors.New("returned incorrect vm interface")
	}

	klog.Infof("Found vm for machine %s", s.scope.Name())

	// vmExtSpec := &virtualmachineextensions.Spec{
	// 	Name:   "startupScript",
	// 	VMName: s.scope.Name(),
	// }

	// vmExt, err := s.virtualMachinesExtSvc.Get(ctx, vmExtSpec)
	// if err != nil && vmExt == nil {
	// 	return false, nil
	// }

	// if err != nil {
	// 	return false, errors.Wrapf(err, "failed to get vm extension")
	// }

	vmState := v1alpha1.VMState(*vm.ProvisioningState)

	s.scope.MachineStatus.VMID = vm.ID
	s.scope.MachineStatus.VMState = &vmState
	return true, nil
}
