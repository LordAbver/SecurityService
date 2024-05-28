using System;
using System.Collections.Concurrent;
using System.Collections.Generic;


namespace XXX.Automation.YYY.Services.SecurityService;


public static class ApplicationInfo
{
    public readonly static Guid ApplicationGuid = new("2370bd22-bb2e-43d4-b816-cff4f6453aa0");
}

internal class SecurityPolicyInfo
{
    /// <summary>
    /// Maps the application guid to the policy types
    /// </summary>
    public static readonly ConcurrentDictionary<Guid, List<string>> Policies;


    static SecurityPolicyInfo()
    {
        Policies = new ConcurrentDictionary<Guid, List<string>>();

        // Set the policies for the Service X
        Policies.TryAdd(new Guid("a8e9274d-83e4-451c-82d4-7679f1f004ec"), ["WebClient"]);
    }
}

/// <summary>
/// Type of the subscription to the security policy changes notifications
/// </summary>
public enum SubscriptionType
{
    /// <summary>
    /// The notify about changed security policies to clients will be sent 
    /// </summary>
    NotifyOnlyChanges,
    /// <summary>
    /// The changed security policies to clients will be sent
    /// </summary>
    ProvideChangesContents
}

/// <summary>
/// Type of the notification sent to client
/// </summary>
internal enum SecurityNotificationType
{
    /// <summary>
    /// Send notify about changed security policies to clients
    /// </summary>
    OnSecurityPolicyChanged,
    /// <summary>
    /// Send changed security policies to clients
    /// </summary>
    OnSecurityPolicyContentsChanged
}

/// <summary>
/// Type of client connectivity state
/// </summary>
internal enum ClientConnectionState
{
    /// <summary>
    /// Normal working state of client (default value)
    /// </summary>
    Alive,
    /// <summary>
    /// First attempt to send the message was not successful,
    /// after reconnection the second attempt might be done
    /// </summary>
    Disconnected,
    /// <summary>
    /// The message to the client cannot be sent during the second attempt
    /// </summary>
    Dead
}

[Serializable]
public class SecurityServiceException : Exception
{
    public SecurityServiceException() { }
    public SecurityServiceException(string message) : base(message) { }
    public SecurityServiceException(string message, Exception inner) : base(message, inner) { }
    protected SecurityServiceException(System.Runtime.Serialization.SerializationInfo info,
                                       System.Runtime.Serialization.StreamingContext context)
        : base(info, context) { }
}
