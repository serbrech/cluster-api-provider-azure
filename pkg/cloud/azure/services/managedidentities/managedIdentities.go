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

package managedidentities

import (
	"context"

	"github.com/pkg/errors"

	"github.com/Azure/azure-sdk-for-go/services/msi/mgmt/2018-11-30/msi"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/cloud/azure"
)

// Spec specification for user assigned identities
type Spec struct {
	// ID - The id of the created identity.
	ID string
	// Name - The name of the created identity.
	Name string
}

// Get provides information about a resource group.
func (s *Service) Get(ctx context.Context, spec azure.Spec) (interface{}, error) {
	identitySpec, ok := spec.(*Spec)
	if !ok {
		return msi.Identity{}, errors.New("invalid managed identity specification")
	}
	//Get(ctx context.Context, resourceGroupName string, resourceName string)
	identity, err := s.Client.Get(ctx, s.Scope.ResourceGroup(), identitySpec.Name)
	if err != nil && azure.ResourceNotFound(err) {
		return nil, errors.Wrapf(err, "identity %s is not found", identitySpec.Name)
	} else if err != nil {
		return identity, err
	}

	return identity, nil
}

// CreateOrUpdate creates or updates a resource group.
func (s *Service) CreateOrUpdate(ctx context.Context, spec azure.Spec) error {
	return errors.New("not implemented")
}

// Delete deletes the resource group with the provided name.
func (s *Service) Delete(ctx context.Context, spec azure.Spec) error {
	return errors.New("not implemented")
}
