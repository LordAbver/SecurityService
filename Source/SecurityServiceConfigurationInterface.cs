using Harris.Automation.ADC.Services.Common.Configuration;
using System.Configuration;
using System.IO;
using System.ServiceModel;


namespace XXX.Automation.YYY.Services.SecurityService;

[ServiceBehavior(InstanceContextMode = InstanceContextMode.Single)]
public class SecurityServiceConfigurationInterface : ConfigurationInterface
{
    public SecurityServiceConfigurationInterface()
        : base(Config.Instance)
    {
        Config.Instance.Load(
            Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().CodeBase) +
            ConfigurationManager.AppSettings["ConfigFilePath"]);
    }
}
