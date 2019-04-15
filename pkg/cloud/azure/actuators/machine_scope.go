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

package actuators

import (
	"context"

	"github.com/Azure/go-autorest/autorest"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types" //metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/apis/azureprovider/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const (
	// AzureCredsSubscriptionIDKey subcription ID
	AzureCredsSubscriptionIDKey = "azure_subscription_id"
	// AzureCredsClientIDKey client id
	AzureCredsClientIDKey = "azure_client_id"
	// AzureCredsClientSecretKey client secret
	AzureCredsClientSecretKey = "azure_client_secret"
	// AzureCredsTenantIDKey tenant ID
	AzureCredsTenantIDKey = "azure_tenant_id"
	// AzureCredsResourceGroupKey resource group
	AzureCredsResourceGroupKey = "azure_resourcegroup"
	// AzureCredsRegionKey region
	AzureCredsRegionKey = "azure_region"
)

// MachineScopeParams defines the input parameters used to create a new MachineScope.
type MachineScopeParams struct {
	Machine *machinev1.Machine
	Client  client.Client
}

// NewMachineScope creates a new MachineScope from the supplied parameters.
// This is meant to be called for each machine actuator operation.
func NewMachineScope(params MachineScopeParams) (*MachineScope, error) {
	machineConfig, err := MachineConfigFromProviderSpec(params.Client, params.Machine.Spec.ProviderSpec)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get machine config")
	}

	machineStatus, err := v1alpha1.MachineStatusFromProviderStatus(params.Machine.Status.ProviderStatus)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get machine provider status")
	}

	env, err := auth.ParseAzureEnvironment("AzurePublicCloud")
	if err != nil {
		return nil, err
	}

	authConfig, err := getAuthConfig(machineConfig, params.Client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse azure auth configuration")
	}

	token, err := getServicePrincipalToken(authConfig, env)
	if err != nil {
		return nil, err
	}

	authorizer, err := autorest.NewBearerAuthorizer(token), nil
	if err != nil {
		return nil, errors.Errorf("failed to create azure session: %v", err)
	}

	return &MachineScope{
		Authorizer:     authorizer,
		SubscriptionID: string(authConfig.SubscriptionID),
		Region:         string(authConfig.Region),
		Group:          string(authConfig.ResourceGroup),
		Machine:        params.Machine,
		MachineClient:  params.Client,
		MachineConfig:  machineConfig,
		MachineStatus:  machineStatus,
	}, nil
}

// MachineScope defines a scope defined around a machine and its cluster.
type MachineScope struct {
	SubscriptionID string
	Region         string
	Group          string
	Authorizer     autorest.Authorizer
	Machine        *machinev1.Machine
	MachineClient  client.Client
	MachineConfig  *v1alpha1.AzureMachineProviderSpec
	MachineStatus  *v1alpha1.AzureMachineProviderStatus
}

// Name returns the machine name.
func (m *MachineScope) Name() string {
	return m.Machine.Name
}

// Namespace returns the machine namespace.
func (m *MachineScope) Namespace() string {
	return m.Machine.Namespace
}

// Role returns the machine role from the labels.
func (m *MachineScope) Role() string {
	return m.Machine.Labels["set"]
}

// Location returns the machine location.
func (m *MachineScope) Location() string {
	return m.Region
}

// ResourceGroup returns the machine resource group.
func (m *MachineScope) ResourceGroup() string {
	return m.Group
}

func (m *MachineScope) storeMachineStatus(machine *machinev1.Machine) error {
	ext, err := v1alpha1.EncodeMachineStatus(m.MachineStatus)
	if err != nil {
		return err
	}

	m.Machine.Status.DeepCopyInto(&machine.Status)
	machine.Status.ProviderStatus = ext
	return m.MachineClient.Status().Update(context.Background(), machine)
}

// Close the MachineScope by updating the machine spec, machine status.
func (m *MachineScope) Close() {
	if m.MachineClient == nil {
		return
	}

	err := m.storeMachineStatus(m.Machine)
	if err != nil {
		klog.Errorf("[machinescope] failed to store provider status for machine %q in namespace %q: %v", m.Machine.Name, m.Machine.Namespace, err)
	}
}

// // providerConfigFromMachine gets the machine provider config MachineSetSpec from the
// // specified cluster-api MachineSpec.
// func providerConfigFromMachine(client client.Client, machine *machinev1.Machine, codec *providerconfigv1.AWSProviderConfigCodec) (*providerconfigv1.AWSMachineProviderConfig, error) {
// 	var providerSpecRawExtention runtime.RawExtension

// 	providerSpec := machine.Spec.ProviderSpec
// 	if providerSpec.Value == nil && providerSpec.ValueFrom == nil {
// 		return nil, fmt.Errorf("unable to find machine provider config: neither Spec.ProviderSpec.Value nor Spec.ProviderSpec.ValueFrom set")
// 	}

// 	// If no providerSpec.Value then we lookup for machineClass
// 	if providerSpec.Value != nil {
// 		providerSpecRawExtention = *providerSpec.Value
// 	} else {
// 		if providerSpec.ValueFrom.MachineClass == nil {
// 			return nil, fmt.Errorf("unable to find MachineClass on Spec.ProviderSpec.ValueFrom")
// 		}
// 		machineClass := &machinev1.MachineClass{}
// 		key := types.NamespacedName{
// 			Namespace: providerSpec.ValueFrom.MachineClass.Namespace,
// 			Name:      providerSpec.ValueFrom.MachineClass.Name,
// 		}
// 		if err := client.Get(context.Background(), key, machineClass); err != nil {
// 			return nil, err
// 		}
// 		providerSpecRawExtention = machineClass.ProviderSpec
// 	}

// 	var config providerconfigv1.AWSMachineProviderConfig
// 	if err := codec.DecodeProviderSpec(&machinev1.ProviderSpec{Value: &providerSpecRawExtention}, &config); err != nil {
// 		return nil, err
// 	}
// 	return &config, nil
// }

// MachineConfigFromProviderSpec tries to decode the JSON-encoded spec, falling back on getting a MachineClass if the value is absent.
func MachineConfigFromProviderSpec(clusterClient client.Client, providerConfig machinev1.ProviderSpec) (*v1alpha1.AzureMachineProviderSpec, error) {
	var config v1alpha1.AzureMachineProviderSpec
	if providerConfig.Value != nil {
		klog.V(4).Info("Decoding ProviderConfig from Value")
		return unmarshalProviderSpec(providerConfig.Value)
	}

	if providerConfig.ValueFrom != nil && providerConfig.ValueFrom.MachineClass != nil {
		ref := providerConfig.ValueFrom.MachineClass
		klog.V(4).Info("Decoding ProviderConfig from MachineClass")
		klog.V(6).Infof("ref: %v", ref)
		if ref.Provider != "" && ref.Provider != "azure" {
			return nil, errors.Errorf("Unsupported provider: %q", ref.Provider)
		}

		if len(ref.Namespace) > 0 && len(ref.Name) > 0 {
			klog.V(4).Infof("Getting MachineClass: %s/%s", ref.Namespace, ref.Name)
			machineClass := &machinev1.MachineClass{}
			key := types.NamespacedName{
				Namespace: providerConfig.ValueFrom.MachineClass.Namespace,
				Name:      providerConfig.ValueFrom.MachineClass.Name,
			}
			if err := clusterClient.Get(context.Background(), key, machineClass); err != nil {
				return nil, err
			}

			klog.V(6).Infof("Retrieved MachineClass: %+v", machineClass)
			providerConfig.Value = &machineClass.ProviderSpec
			return unmarshalProviderSpec(&machineClass.ProviderSpec)
		}
	}

	return &config, nil
}

func unmarshalProviderSpec(spec *runtime.RawExtension) (*v1alpha1.AzureMachineProviderSpec, error) {
	var config v1alpha1.AzureMachineProviderSpec
	if spec != nil {
		if err := yaml.Unmarshal(spec.Raw, &config); err != nil {
			return nil, err
		}
	}
	klog.V(6).Infof("Found ProviderSpec: %+v", config)
	return &config, nil
}
