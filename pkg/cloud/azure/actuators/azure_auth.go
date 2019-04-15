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
	"fmt"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
	"sigs.k8s.io/cluster-api-provider-azure/pkg/apis/azureprovider/v1alpha1"
	controller "sigs.k8s.io/controller-runtime/pkg/client"
)

//ref https://github.com/kubernetes/kubernetes/blob/master/pkg/cloudprovider/providers/azure/auth/azure_auth.go#L32
type azureAuthConfig struct {
	// The cloud environment identifier. Takes values from https://github.com/Azure/go-autorest/blob/ec5f4903f77ed9927ac95b19ab8e44ada64c1356/autorest/azure/environments.go#L13
	Cloud string `json:"cloud" yaml:"cloud"`
	// The AAD Tenant ID for the Subscription that the cluster is deployed in
	TenantID string `json:"tenantId" yaml:"tenantId"`
	// The ClientID for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientID string `json:"aadClientId" yaml:"aadClientId"`
	// The ClientSecret for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientSecret string `json:"aadClientSecret" yaml:"aadClientSecret"`
	// Use managed service identity for the virtual machine to access Azure ARM APIs
	UseManagedIdentityExtension bool `json:"useManagedIdentityExtension" yaml:"useManagedIdentityExtension"`
	// UserAssignedIdentityID contains the Client ID of the user assigned MSI which is assigned to the underlying VMs. If empty the user assigned identity is not used.
	// More details of the user assigned identity can be found at: https://docs.microsoft.com/en-us/azure/active-directory/managed-service-identity/overview
	// For the user assigned identity specified here to be used, the UseManagedIdentityExtension has to be set to true.
	UserAssignedIdentityID string `json:"userAssignedIdentityID" yaml:"userAssignedIdentityID"`
	// The ID of the Azure Subscription that the cluster is deployed in
	SubscriptionID string `json:"subscriptionId" yaml:"subscriptionId"`

	ResourceGroup string
	Region        string
}

func getAuthConfig(machineConfig *v1alpha1.AzureMachineProviderSpec, client controller.Client) (*azureAuthConfig, error) {
	secretName := fmt.Sprintf("%s/%s", machineConfig.CredentialsSecret.Namespace, machineConfig.CredentialsSecret.Name)

	var secret corev1.Secret
	if err := client.Get(context.Background(), controller.ObjectKey{Namespace: machineConfig.CredentialsSecret.Namespace, Name: machineConfig.CredentialsSecret.Name}, &secret); err != nil {
		return nil, err
	}
	subscriptionID, ok := secret.Data[AzureCredsSubscriptionIDKey]
	if !ok {
		return nil, fmt.Errorf("Azure subscription id %v did not contain key %v",
			secretName, AzureCredsSubscriptionIDKey)
	}
	clientID, ok := secret.Data[AzureCredsClientIDKey]
	if !ok {
		return nil, fmt.Errorf("Azure client id %v did not contain key %v",
			secretName, AzureCredsClientIDKey)
	}
	clientSecret, ok := secret.Data[AzureCredsClientSecretKey]
	if !ok {
		return nil, fmt.Errorf("Azure client secret %v did not contain key %v",
			secretName, AzureCredsClientSecretKey)
	}
	tenantID, ok := secret.Data[AzureCredsTenantIDKey]
	if !ok {
		return nil, fmt.Errorf("Azure tenant id %v did not contain key %v",
			secretName, AzureCredsTenantIDKey)
	}

	resourceGroup, ok := secret.Data[AzureCredsResourceGroupKey]
	if !ok {
		return nil, fmt.Errorf("Azure resource group %v did not contain key %v",
			secretName, AzureCredsResourceGroupKey)
	}
	region, ok := secret.Data[AzureCredsRegionKey]
	if !ok {
		return nil, fmt.Errorf("Azure region %v did not contain key %v",
			secretName, AzureCredsRegionKey)
	}

	return &azureAuthConfig{
		AADClientID:     string(clientID),
		AADClientSecret: string(clientSecret),
		Cloud:           "AzurePublicCloud",
		SubscriptionID:  string(subscriptionID),
		TenantID:        string(tenantID),
		ResourceGroup:   string(resourceGroup),
		Region:          string(region),
		UseManagedIdentityExtension: machineConfig.UseManagedIdentityExtension,
		UserAssignedIdentityID:      machineConfig.UserAssignedIdentityID,
	}, nil
}

func getServicePrincipalToken(config *azureAuthConfig, env *azure.Environment) (*adal.ServicePrincipalToken, error) {
	if config.UseManagedIdentityExtension {
		klog.V(2).Infoln("azure: using managed identity extension to retrieve access token")
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, fmt.Errorf("Getting the managed service identity endpoint: %v", err)
		}
		if len(config.UserAssignedIdentityID) > 0 {
			klog.V(4).Info("azure: using User Assigned MSI ID to retrieve access token")
			return adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint,
				env.ServiceManagementEndpoint,
				config.UserAssignedIdentityID)
		}
		klog.V(4).Info("azure: using System Assigned MSI to retrieve access token")
		return adal.NewServicePrincipalTokenFromMSI(
			msiEndpoint,
			env.ServiceManagementEndpoint)
	}

	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if len(config.AADClientSecret) > 0 {
		klog.V(2).Infoln("azure: using client_id+client_secret to retrieve access token")
		return adal.NewServicePrincipalToken(
			*oauthConfig,
			config.AADClientID,
			config.AADClientSecret,
			env.ServiceManagementEndpoint)
	}

	return nil, fmt.Errorf("No credentials provided for AAD application %s", config.AADClientID)
}
