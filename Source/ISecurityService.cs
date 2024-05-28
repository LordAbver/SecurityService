using System;
using System.Collections.Generic;
using System.ServiceModel;


namespace XXX.Automation.YYY.Services.SecurityService
{
    /// <summary>
    /// The interface of Security Service.
    /// </summary>
    [ServiceContract(CallbackContract = typeof(ISecurityServiceClient))]
    public interface ISecurityService : IHeartbeatableService
    {
        /// <summary>
        /// Load license file content through the Security Service UI
        /// </summary>
        /// <param name="fileContent">Content of the license file</param>
        /// <returns>License file validation result</returns>
        [OperationContract]
        bool LoadLicenseFile(string fileContent);

        /// <summary>
        /// Request the policy by the YYY product
        /// </summary>
        /// <param name="applicationId">YYY product id</param>
        /// <returns>List of serialized policy data</returns>
        [OperationContract]
        IEnumerable<string> GetSecurityPolicy(Guid applicationId);

        /// <summary>
        /// Subscribe to the security policy changes
        /// </summary>
        /// <param name="applicationId">Application guid of the calling client</param>
        /// <param name="subscriptionType">Specify the type of subscription</param>
        /// <returns>'True' if the subscription succeeded, 
        /// 'False' if the subscription failed</returns>
        [OperationContract]
        bool RegisterSecurityPolicyChangesListener(Guid applicationId, SubscriptionType subscriptionType);

        /// <summary>
        /// Unsubscribe from the security policy changes notifications
        /// </summary>
        [OperationContract(IsOneWay = true)]
        void UnregisterSecurityPolicyChangesListener();
    }

    /// <summary>
    /// The interface of Security Service callbacks
    /// </summary>
    public interface ISecurityServiceClient
    {
        /// <summary>
        /// Notify client about changed license
        /// </summary>
        [OperationContract(IsOneWay = true)]
        void OnSecurityPolicyChanged();

        /// <summary>
        /// Notify client about changed license and provide new license information
        /// </summary>
        /// <param name="newPolicyData">New license parameters corresponding to only current client</param>
        [OperationContract(IsOneWay = true)]
        void OnSecurityPolicyContentsChanged(IEnumerable<string> newPolicyData);

        /// <summary>
        /// Check availability of a client
        /// </summary>
        [OperationContract(IsOneWay = true)]
        void CheckAvailability();
    }
}
