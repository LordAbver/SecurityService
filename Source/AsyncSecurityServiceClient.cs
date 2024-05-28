using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Threading;


namespace XXX.Automation.YYY.Services.SecurityService;

/// <summary>
/// Async callback class
/// </summary>
internal sealed class AsyncSecurityServiceClient : IDisposable, ISecurityServiceClient
{
    #region Variables and properties

    private Thread _callbackThread;
    private volatile ClientConnectionState _state;
    private bool _isDisposed;

    private ConcurrentQueue<SecurityServiceCallbackInfo> _callbackEvents;
    private readonly EventWaitHandle _handle;
    private readonly ISecurityServiceClient _callback;

    public ClientConnectionState State
    {
        get { return _state; }
        private set { _state = value; }
    }

    public Guid ApplicationId { get; private set; }
    public SubscriptionType SecurityPolicyChangesSubscriptionType { get; set; }

    #endregion

    #region Class methods

    public AsyncSecurityServiceClient(ISecurityServiceClient callback, Guid applicationId, SubscriptionType subscriptionType)
    {
        _callback = callback;
        _handle = new ManualResetEvent(false);
        _callbackEvents = new ConcurrentQueue<SecurityServiceCallbackInfo>();

        ApplicationId = applicationId;
        SecurityPolicyChangesSubscriptionType = subscriptionType;

        Start();
    }

    ~AsyncSecurityServiceClient()
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
        if (!_isDisposed)
        {
            // Free the unmanaged resources
            Stop();
            _callbackThread = null;

            if (disposing)
            {
                // Free the managed resources
                _handle.Dispose();
                _callbackEvents = null;

                GC.Collect();
                GC.SuppressFinalize(this);
            }

            _isDisposed = true;
        }
    }

    #endregion

    #region Private and internal working methods

    private void Start()
    {
        if (_callbackThread != null)
        {
            if (_callbackThread.ThreadState != ThreadState.Running
                && _callbackThread.ThreadState != ThreadState.WaitSleepJoin)
            {
                _callbackThread = new Thread(ExecuteCallbacks) { Name = "SecurityCallbackThread" };
                _callbackThread.Start();
            }
        }
        else
        {
            _callbackThread = new Thread(ExecuteCallbacks) { Name = "SecurityCallbackThread" };
            _callbackThread.Start();
        }
    }

    private void Stop()
    {
        if (_callbackThread != null)
            if (_callbackThread.ThreadState == ThreadState.Running
            || _callbackThread.ThreadState == ThreadState.WaitSleepJoin)
            {
                State = ClientConnectionState.Dead;
                _callbackThread.Interrupt();
                _callbackThread.Join();
            }
    }

    private void ExecuteCallbacks()
    {
        const string errorTemplate = "Security Service client was not able to send the message to a client because of ";

        try
        {
            while (State == ClientConnectionState.Alive)
            {
                _handle.WaitOne();
                _handle.Reset();

                while (!_callbackEvents.IsEmpty)
                {
                    // Get the message to send
                    _callbackEvents.TryPeek(out SecurityServiceCallbackInfo info);

                    try
                    {
                        // Try to send the message 
                        info.ExecuteCallback(_callback);

                        // Remove sent message from the queue
                        _callbackEvents.TryDequeue(out info);
                    }
                    catch (Exception ex)
                    {
                        if (ex is CommunicationException ||
                            ex is TimeoutException ||
                            ex is ObjectDisposedException)
                        {
                            if (State == ClientConnectionState.Alive)
                            {
                                ServiceLogger.Warning(errorTemplate + ex.GetType().Name);

                                // Try to send the message in next time iteration
                                State = ClientConnectionState.Disconnected;
                                Thread.Sleep(5000);
                            }
                            else
                            {
                                ServiceLogger.Error(errorTemplate + ex.GetType().Name, ex);

                                // Second attempt was unsuccessful
                                State = ClientConnectionState.Dead;
                                break;
                            }
                        }
                        else
                            throw;
                    }
                }
            }
        }
        catch (ThreadInterruptedException)
        {
        }
    }

    internal bool IsCurrentCallback(ISecurityServiceClient callback)
    {
        return callback.Equals(_callback);
    }

    #endregion

    #region Public working methods

    /// <summary>
    /// Notify the connected client about the updated license policy
    /// </summary>
    public void OnSecurityPolicyChanged()
    {
        _callbackEvents.Enqueue(new SecurityPolicyChangedCallbackInfo());
        _handle.Set();
    }

    /// <summary>
    /// Send the updated license policy to connected client
    /// </summary>
    public void OnSecurityPolicyContentsChanged(IEnumerable<string> newPolicyData)
    {
        _callbackEvents.Enqueue(new SecurityPolicyContentsChangedCallbackInfo(newPolicyData));
        _handle.Set();
    }

    /// <summary>
    /// CheckAvailability does nothing for this type of client because 
    /// it is more rational to call the WCF callback twice than polling the client 
    /// as the changes of the license policies are expected to be rare
    /// </summary>
    public void CheckAvailability()
    {
    }

    #endregion

    #region Standard methods and overrides

    public override bool Equals(object obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        return Equals(obj as AsyncSecurityServiceClient);
    }

    public bool Equals(AsyncSecurityServiceClient other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Equals(other._callback, _callback);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            return _callback != null ? _callback.GetHashCode() : 0;
        }
    }

    public static bool operator ==(AsyncSecurityServiceClient left, AsyncSecurityServiceClient right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(AsyncSecurityServiceClient left, AsyncSecurityServiceClient right)
    {
        return !Equals(left, right);
    }

    #endregion
}

#region CallbackInfo classes

internal abstract class SecurityServiceCallbackInfo
{
    public abstract void ExecuteCallback(ISecurityServiceClient client);
}

internal class SecurityPolicyChangedCallbackInfo : SecurityServiceCallbackInfo
{
    public override void ExecuteCallback(ISecurityServiceClient client)
    {
        client.OnSecurityPolicyChanged();
    }
}

internal class SecurityPolicyContentsChangedCallbackInfo(IEnumerable<string> newPolicyData) : SecurityServiceCallbackInfo
{
    public IEnumerable<string> NewPolicyData { get; private set; } = newPolicyData.ToArray();

    public override void ExecuteCallback(ISecurityServiceClient client)
    {
        client.OnSecurityPolicyContentsChanged(NewPolicyData);
    }
}

#endregion
