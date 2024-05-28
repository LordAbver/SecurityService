using Harris.Automation.ADC.Services.Common.Configuration;

namespace XXX.Automation.YYY.Services.SecurityService;
public sealed class Config : SingletonConfiguration<SecurityServiceConfiguration>
{
    private static Config _instance;


    public static Config Instance
    {
        get
        {
            _instance ??= new Config();

            return _instance;
        }
    }

    /// <summary>
    /// Constructor
    /// </summary>
    private Config()
        : base()
    {
    }
}
