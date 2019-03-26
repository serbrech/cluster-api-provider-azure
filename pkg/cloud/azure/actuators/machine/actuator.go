/*
Copyright 2018 The Kubernetes Authors.

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

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	apierrors "github.com/openshift/cluster-api/pkg/errors"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/cloud/azure/actuators"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	createEventAction = "Create"
	updateEventAction = "Update"
	deleteEventAction = "Delete"
	noEventAction     = ""
)

//+kubebuilder:rbac:groups=azureprovider.k8s.io,resources=azuremachineproviderconfigs;azuremachineproviderstatuses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cluster.k8s.io,resources=machines;machines/status;machinedeployments;machinedeployments/status;machinesets;machinesets/status;machineclasses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cluster.k8s.io,resources=clusters;clusters/status,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=nodes;events,verbs=get;list;watch;create;update;patch;delete

// Actuator is responsible for performing machine reconciliation.
type Actuator struct {
	client        client.Client
	EventRecorder record.EventRecorder
}

// ActuatorParams holds parameter information for Actuator.
type ActuatorParams struct {
	Client        client.Client
	EventRecorder record.EventRecorder
}

// NewActuator returns an actuator.
func NewActuator(params ActuatorParams) *Actuator {
	return &Actuator{
		client:        params.Client,
		EventRecorder: params.EventRecorder,
	}
}

// Set corresponding event based on error. It also returns the original error
// for convenience, so callers can do "return handleMachineError(...)".
func (a *Actuator) handleMachineError(machine *machinev1.Machine, err *apierrors.MachineError, eventAction string) error {
	if eventAction != noEventAction {
		a.EventRecorder.Eventf(machine, corev1.EventTypeWarning, "Failed"+eventAction, "%v", err.Reason)
	}

	klog.Errorf("Machine error: %v", err.Message)
	return err
}

// Create creates a machine and is invoked by the machine controller.
func (a *Actuator) Create(ctx context.Context, cluster *machinev1.Cluster, machine *machinev1.Machine) error {
	klog.Infof("Creating machine %v", machine.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Client: a.client})
	if err != nil {
		return errors.Errorf("failed to create scope: %+v", err)
	}
	defer scope.Close()

	err = NewReconciler(scope).Create(context.Background())
	if err != nil {
		klog.Errorf("failed to reconcile machine %s: %v", machine.Name, err)
		return a.handleMachineError(machine, apierrors.CreateMachine("%v", err), createEventAction)
	}

	return nil
}

// Delete deletes a machine and is invoked by the Machine Controller.
func (a *Actuator) Delete(ctx context.Context, cluster *machinev1.Cluster, machine *machinev1.Machine) error {
	klog.Infof("Deleting machine %v.", machine.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Client: a.client})
	if err != nil {
		return errors.Wrapf(err, "failed to create scope")
	}

	defer scope.Close()

	err = NewReconciler(scope).Delete(context.Background())
	if err != nil {
		klog.Errorf("failed to delete machine %s: %v", machine.Name, err)
		return a.handleMachineError(machine, apierrors.DeleteMachine("%v", err), noEventAction)
	}

	return nil
}

// Update updates a machine and is invoked by the Machine Controller.
// If the Update attempts to mutate any immutable state, the method will error
// and no updates will be performed.
func (a *Actuator) Update(ctx context.Context, cluster *machinev1.Cluster, machine *machinev1.Machine) error {
	klog.Infof("Updating machine %v.", machine.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Client: a.client})
	if err != nil {
		return errors.Errorf("failed to create scope: %+v", err)
	}

	defer scope.Close()

	err = NewReconciler(scope).Update(context.Background())
	if err != nil {
		klog.Errorf("failed to update machine %s: %v", machine.Name, err)
		return a.handleMachineError(machine, apierrors.UpdateMachine("%v", err), updateEventAction)
	}

	return nil
}

// Exists test for the existence of a machine and is invoked by the Machine Controller
func (a *Actuator) Exists(ctx context.Context, cluster *machinev1.Cluster, machine *machinev1.Machine) (bool, error) {
	klog.Infof("Checking if machine %v exists", machine.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Client: a.client})
	if err != nil {
		return false, errors.Errorf("failed to create scope: %+v", err)
	}

	defer scope.Close()

	isExists, err := NewReconciler(scope).Exists(context.Background())
	if err != nil {
		klog.Errorf("failed to check machine %s exists: %v", machine.Name, err)
	}

	return isExists, err
}
