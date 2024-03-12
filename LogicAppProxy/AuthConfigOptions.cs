namespace LogicAppProxy;

public class LogicAppsOptions
{
    public WorkflowAuthType[]? AuthConfig { get; set; }
}

public class WorkflowAuthType
{
    public string? WorkflowName { get; set; }
    public string? AuthType { get; set; }
}
