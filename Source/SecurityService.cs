using Harris.Automation.ADC.Services.Common.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.Xml.Linq;


namespace XXX.Automation.YYY.Services.SecurityService;

[ServiceBehavior(InstanceContextMode = InstanceContextMode.Single)]
public class SecurityService : IDisposable, ISecurityService
{
    #region Private types

    private class XElementNameEqualityComparer : IEqualityComparer<XElement>
    {
        public bool Equals(XElement element1, XElement element2)
        {
            return element1.Name.Equals(element2.Name);
        }

        public int GetHashCode(XElement element)
        {
            return element.Name.GetHashCode();
        }
    }

    private class XElementContentsEqualityComparer : IEqualityComparer<XElement>
    {
        public bool Equals(XElement element1, XElement element2)
        {
            if (!element1.Name.Equals(element2.Name))
                return false;

            return XNode.DeepEquals(element1, element2);
        }

        public int GetHashCode(XElement element)
        {
            return element.ToString().GetHashCode();
        }
    }

    private enum NodeAction
    {
        Added,
        Updated,
        Removed
    }

    #endregion

    #region Consts, variables

    private const string TARGET_NAMESPACE = "http://XXX/Automation/YYY/SecurityPolicy";
    private const string BRAND_NAME = "XXX BroYYYast";
    private XDocument _policyDocument;

    private volatile bool _disposed;
    private List<AsyncSecurityServiceClient> _subscribers;
    private object _subscribersLock;
    private Func<ISecurityServiceClient> _callbackCreator;

    #endregion

    #region Class methods

    public SecurityService()
    {
        SecurityServiceCreate(OperationContext.Current.GetCallbackChannel<ISecurityServiceClient>);
    }

#if DEBUG
    public SecurityService(Func<ISecurityServiceClient> callbackCreator)
    {
        SecurityServiceCreate(callbackCreator);
    }
#endif

    public void SecurityServiceCreate(Func<ISecurityServiceClient> callbackCreator)
    {
        _subscribersLock = new object();
        _subscribers = [];
        _callbackCreator = callbackCreator ?? throw new ArgumentNullException("callbackCreator");

        // Try to load the document from the file
        try
        {
            _policyDocument = XDocument.Parse(GetLicenseFromFile());
        }
        catch (System.Xml.XmlException)
        {
        }
    }

    ~SecurityService()
    {
        Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            // Free the unmanaged sources
            lock (_subscribersLock)
            {
                foreach (var asyncServiceClient in _subscribers)
                {
                    asyncServiceClient.Dispose();
                }
                _subscribers.Clear();
            }

            if (disposing)
            {
            }
            _disposed = true;
        }
    }

    #endregion

    #region Private methods

    private string GetLicenseFileDirectory()
    {
        string fileDirectory;

        string configuredFileDirectory = Path.GetDirectoryName(Config.Instance.ConfigObject.LicenseFilePath);
        if (Path.IsPathRooted(configuredFileDirectory))
        {
            fileDirectory = configuredFileDirectory;
        }
        else
        {
            string assembliesPath = new Uri(System.Reflection.Assembly.GetExecutingAssembly().CodeBase).AbsolutePath;
            string assembliesDirectory = Path.GetDirectoryName(Uri.UnescapeDataString(assembliesPath));

            if (!string.IsNullOrWhiteSpace(assembliesDirectory) && !string.IsNullOrWhiteSpace(configuredFileDirectory))
                fileDirectory = Path.Combine(assembliesDirectory, configuredFileDirectory);
            else if (!string.IsNullOrWhiteSpace(assembliesDirectory))
                fileDirectory = Path.Combine(assembliesDirectory, "license");
            else
                fileDirectory = string.Empty;
        }
        return fileDirectory;
    }

    private bool ValidateLicenseXml(string fileContent, out XDocument parsedDocument)
    {
        parsedDocument = null;

        string decryptedText;
        try
        {
            decryptedText = SecurityPolicyAlgorithm.SecurityPolicyAlgorithm.Decrypt(fileContent);
        }
        catch (SecurityPolicyAlgorithmException)
        {
            return false;
        }

        XDocument testDoc;
        try
        {
            testDoc = XDocument.Parse(decryptedText);
        }
        catch (System.Xml.XmlException)
        {
            return false;
        }
        var testBrand = testDoc.Descendants(XName.Get("BrandName", TARGET_NAMESPACE)).FirstOrDefault();

        if (testBrand == null || testBrand.Value != BRAND_NAME)
            return false;

        parsedDocument = testDoc;
        return true;
    }

    private void StoreLicenseToFile(string fileContent)
    {
        // Create directory
        string fileDirectory = GetLicenseFileDirectory();
        if (string.IsNullOrWhiteSpace(fileDirectory))
            fileDirectory = "license";

        if (!Directory.Exists(fileDirectory))
        {
            Directory.CreateDirectory(fileDirectory);
            ServiceLogger.Verbose("Created a directory for the new license file: " + fileDirectory);
        }

        // Write to file
        string fileName = Path.GetFileName(Path.GetFullPath(Config.Instance.ConfigObject.LicenseFilePath));
        if (string.IsNullOrWhiteSpace(fileName))
            fileName = "YYYLicense.lic";

        string filePath = Path.Combine(fileDirectory, fileName);
        ServiceLogger.Debug("Absolute path for the new license file: " + filePath);

        using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
        {
            using (var sr = new StreamWriter(fs))
            {
                sr.Write(fileContent);
            }
        }
    }

    private string GetLicenseFromFile()
    {
        string fileDirectory = GetLicenseFileDirectory();
        if (string.IsNullOrWhiteSpace(fileDirectory))
            fileDirectory = "license";

        string fileName = Path.GetFileName(Path.GetFullPath(Config.Instance.ConfigObject.LicenseFilePath));
        if (string.IsNullOrWhiteSpace(fileName))
            fileName = "YYYLicense.lic";

        string filePath = Path.Combine(fileDirectory, fileName);
        ServiceLogger.Debug("Absolute path for the existing license file: " + filePath);

        string result = "";
        if (File.Exists(filePath))
        {
            string licenseDataEncrypted;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                using (var sr = new StreamReader(fs))
                {
                    licenseDataEncrypted = sr.ReadToEnd();
                }
            }

            try
            {
                result = SecurityPolicyAlgorithm.SecurityPolicyAlgorithm.Decrypt(licenseDataEncrypted);
            }
            catch (SecurityPolicyAlgorithmException) { }
        }
        return result;
    }

    private Dictionary<Guid, List<string>> GenerateClientNotifications(NodeAction action, IEnumerable<XElement> nodes)
    {
        var result = new Dictionary<Guid, List<string>>();

        // Find applications affected by the node actions
        if (nodes.Any())
        {
            foreach (var keyValuePolicy in SecurityPolicyInfo.Policies)
            {
                var affectedAppTypes = new string[keyValuePolicy.Value.Count];
                int listCounter = 0;
                foreach (var appType in keyValuePolicy.Value)
                {
                    var policyTag = nodes.FirstOrDefault(node => node.Name.LocalName.StartsWith(appType));
                    if (policyTag != null)
                    {
                        // If the license policy is removed the client should receive the empty policy parameter
                        if (action == NodeAction.Removed)
                            affectedAppTypes[listCounter] = "***Removed***";
                        else
                            affectedAppTypes[listCounter] = policyTag.ToString();
                    }

                    listCounter++;
                }

                // If none is affected - do nothing
                if (affectedAppTypes.All(string.IsNullOrWhiteSpace))
                    continue;

                // If all is affected use only new parameters
                if (affectedAppTypes.All(appType => !string.IsNullOrWhiteSpace(appType)))
                {
                    result.Add(keyValuePolicy.Key,
                               affectedAppTypes.Where(policy => !string.IsNullOrWhiteSpace(policy)).ToList());
                    continue;
                }

                // If some is not affected get info from old parameters
                if (_policyDocument != null)
                {
                    for (int i = 0; i < affectedAppTypes.Length; i++)
                    {
                        if (string.IsNullOrWhiteSpace(affectedAppTypes[i]))
                        {
                            string tagName = keyValuePolicy.Value[i] + "Parameters";
                            var policyTag =
                                _policyDocument.Descendants(XName.Get(tagName, TARGET_NAMESPACE)).FirstOrDefault();
                            if (policyTag != null)
                                affectedAppTypes[i] = policyTag.ToString();
                        }
                    }
                }
                result.Add(keyValuePolicy.Key,
                           affectedAppTypes.Where(policy => !string.IsNullOrWhiteSpace(policy)).ToList());
            }
        }

        return result;
    }

    private bool SendUpdatedLicense(XDocument newLicense)
    {
        if (newLicense == null)
            return false;

        // Compare file contents and identify differences
        var newSecurityPolicyParameters = newLicense.Descendants()
            .Where(element => element.Name.LocalName.EndsWith("Parameters")).ToArray();
        XElement[] oldSecurityPolicyParameters;
        if (_policyDocument != null)
        {
            oldSecurityPolicyParameters = _policyDocument.Descendants()
                .Where(element => element.Name.LocalName.EndsWith("Parameters")).ToArray();
        }
        else
        {
            // The case of initial license loading
            oldSecurityPolicyParameters = new XElement[0];
        }

        // Identify adds
        var addedNodes = newSecurityPolicyParameters
            .Except(oldSecurityPolicyParameters, new XElementNameEqualityComparer());
        // Identify updates
        var updatedNodes = newSecurityPolicyParameters
            .Intersect(oldSecurityPolicyParameters, new XElementNameEqualityComparer())
            .Except(oldSecurityPolicyParameters, new XElementContentsEqualityComparer());
        // Identify removes
        var removedNodes = oldSecurityPolicyParameters
            .Except(newSecurityPolicyParameters, new XElementNameEqualityComparer());

        // Generate application specific notifications
        var notifications = GenerateClientNotifications(NodeAction.Added, addedNodes);
        #region addNotifications implementation
        Action<Dictionary<Guid, List<string>>> addNotifications = preparedNotifications =>
        {
            // Group notifications by application guids because 
            // the one policy type might correspond to different application types
            foreach (var preparedNotification in preparedNotifications)
            {
                if (notifications.ContainsKey(preparedNotification.Key))
                {
                    if (notifications[preparedNotification.Key] == null)
                        notifications[preparedNotification.Key] = [];
                    notifications[preparedNotification.Key].AddRange(preparedNotification.Value);
                }
                else
                    notifications.Add(preparedNotification.Key, preparedNotification.Value);
            }
        };
        #endregion
        addNotifications(GenerateClientNotifications(NodeAction.Updated, updatedNodes));
        addNotifications(GenerateClientNotifications(NodeAction.Removed, removedNodes));

        // Send composed notifications
        bool notifySent = false;
        foreach (var pair in notifications)
        {
            NotifyClients(SecurityNotificationType.OnSecurityPolicyContentsChanged, pair.Key, pair.Value);
            notifySent = true;
        }
        return notifySent;
    }

    #endregion

    #region Straight methods

    public void IsAlive()
    {
    }

    public ServiceVersion GetVersion()
    {
        // Do not return anything because of security constraints
        return null;
    }

    public bool LoadLicenseFile(string fileContent)
    {
        if (_policyDocument == null)
        {
            // Try to load the document from the file 
            // if the license file was copied manually to the input folder
            try
            {
                _policyDocument = XDocument.Parse(GetLicenseFromFile());
            }
            catch (System.Xml.XmlException)
            {
            }
        }

        // Check for validity of received license xml
        if (!ValidateLicenseXml(fileContent, out XDocument newLicense))
            return false;

        // Store the valid license xml
        StoreLicenseToFile(fileContent);

        // Send changed license to subscribers
        bool notifySent = SendUpdatedLicense(newLicense);

        // Set the current policy document
        _policyDocument = newLicense;

        // Notify about changed license
        if (notifySent)
            NotifyClients(SecurityNotificationType.OnSecurityPolicyChanged);

        return true;
    }

    public IEnumerable<string> GetSecurityPolicy(Guid applicationId)
    {
        if (_policyDocument == null)
        {
            // Try to load the document from the file 
            // if the license file was copied manually to the input folder
            try
            {
                _policyDocument = XDocument.Parse(GetLicenseFromFile());
            }
            catch (System.Xml.XmlException)
            {
            }
        }

        var policies = new List<string>();
        if (_policyDocument != null)
        {
            // Try to find the policy types based on the application id
            if (SecurityPolicyInfo.Policies.TryGetValue(applicationId, out List<string> policyTypes))
            {
                // Extract the proper policies
                foreach (var policyType in policyTypes)
                {
                    string tagName = policyType + "Parameters";
                    var policyTag = _policyDocument.Descendants(XName.Get(tagName, TARGET_NAMESPACE)).FirstOrDefault();
                    if (policyTag != null)
                    {
                        string policyXml = policyTag.ToString();
                        if (!string.IsNullOrWhiteSpace(policyXml))
                            policies.Add(policyXml);
                    }
                }
            }
        }
        return policies;
    }

    #endregion

    #region Client subscription and notification

    public bool RegisterSecurityPolicyChangesListener(Guid applicationId, SubscriptionType subscriptionType)
    {
        // Check if the applicationId is known
        if (!SecurityPolicyInfo.Policies.ContainsKey(applicationId))
            return false;

        try
        {
            ISecurityServiceClient callback = _callbackCreator();

            lock (_subscribersLock)
            {
                if (!_subscribers.Any(client => client.IsCurrentCallback(callback)))
                    _subscribers.Add(new AsyncSecurityServiceClient(callback, applicationId, subscriptionType));
            }
            return true;
        }
        catch (CommunicationException ex)
        {
            ServiceLogger.Error("Error while registering SecurityPolicyChangesListener", ex);
            return false;
        }
    }

    public void UnregisterSecurityPolicyChangesListener()
    {
        try
        {
            ISecurityServiceClient callback = _callbackCreator();

            lock (_subscribersLock)
            {
                var currentClient = _subscribers.FirstOrDefault(client => client.IsCurrentCallback(callback));
                if (currentClient != null)
                {
                    currentClient.Dispose();
                    _subscribers.Remove(currentClient);
                }
            }
        }
        catch (CommunicationException ex)
        {
            ServiceLogger.Error("Error while unregistering SecurityPolicyChangesListener", ex);
        }
    }

    private void RemoveDeYYYlients()
    {
        var deYYYlients = _subscribers.Where(item => item.State == ClientConnectionState.Dead).ToList();
        deYYYlients.ForEach(client =>
        {
            client.Dispose();
            _subscribers.Remove(client);
        });
    }

    private object NotifyClients(SecurityNotificationType notificationType, params object[] notifyParameters)
    {
        string notificationName = Enum.GetName(typeof(SecurityNotificationType), notificationType);

        lock (_subscribersLock)
        {
            // Clear dead clients before sending notifications
            RemoveDeYYYlients();

            // Send notifications to clients 
            switch (notificationType)
            {
                case SecurityNotificationType.OnSecurityPolicyChanged:
                    {
                        var targetSubscribers = _subscribers.Where(item =>
                            item.SecurityPolicyChangesSubscriptionType == SubscriptionType.NotifyOnlyChanges);
                        foreach (var client in targetSubscribers)
                        {
                            // Send request
                            client.OnSecurityPolicyChanged();
                        }

                        break;
                    }
                case SecurityNotificationType.OnSecurityPolicyContentsChanged:
                    {
                        // Validate parameters
                        if ((notifyParameters != null) && (notifyParameters.Length == 2) &&
                            (notifyParameters[0] is Guid guid) && (notifyParameters[1] is IEnumerable<string> enumerable))
                        {
                            Guid targetApplicationId = guid;

                            var subscribedApps = _subscribers.Where(client =>
                                client.ApplicationId == targetApplicationId &&
                                client.SecurityPolicyChangesSubscriptionType == SubscriptionType.ProvideChangesContents);

                            foreach (var clientApp in subscribedApps)
                            {
                                // Send request
                                clientApp.OnSecurityPolicyContentsChanged(enumerable);
                            }
                        }
                        else
                        {
                            throw new SecurityServiceException("Invalid parameters were provided to the '" +
                                notificationName + "' notification");
                        }

                        break;
                    }
            }
        }
        return null;
    }

    #endregion
}
