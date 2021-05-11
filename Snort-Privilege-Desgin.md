# Snort Privilege Desgin
In modern operating system, each user or usergroup has its own privilege. Also, only a few users or groups can execute some privileged operations, like accessing /usr/bin, mounting a device to a specific location, reading data from a network interface card (NIC), etc. In this article, I take modern Linux as an example, towards a comprehensive explain of the privilege design in Snort.

Snort, as a intrusion detection system, is highly and frequently required to commnunicate with the NICs during its Data AcQuisition (DAQ) process. Hence, during those operations, Snort process are needed to be bound with a privileged user, allowing it to handle some necessary privileged operations. However, as stated in *Snort::Analyzer Code Insight*, and considering the execuating procedure of Snort, an Analyzer is not always in the DAQ process, nor in the RUNNING state. Such truth implies that **privileges are not always required by the process**.

During the use of Snort, the user may empower enough privileges to Snort when starting the detection by running it with root account. In some scenarios, this is a must since the DAQ operations need that. However, in order to avoid the abuse of privileges, Snort introduces a specific mechanism, which is the so-called privilege dropping.

## Privilege Dropping
Snort implements this mechanism by dynamically check the required privileges of the DAQ moudles, when there is no module that doesn't support unprivileged operation, it will drop the useless privilege to ensure the security. The following functions are defined to check the ability of the moudles to be run under unprivileged process.
```C++
bool SFDAQ::can_run_unprivileged()
{
    // Iterate over the configured modules to see if any of them don't support unprivileged operation
    DAQ_ModuleConfig_h modcfg = daq_config_top_module_config(daqcfg);
    while (modcfg)
    {
        DAQ_Module_h module = daq_module_config_get_module(modcfg);
        if (daq_module_get_type(module) & DAQ_TYPE_NO_UNPRIV)
            return false;
        modcfg = daq_config_next_module_config(daqcfg);
    }
    return true;
}

bool SFDAQInstance::can_start_unprivileged() const
{
    return (daq_instance_get_capabilities(instance) & DAQ_CAPA_UNPRIV_START) != 0;
}
```
Above two functions are called in `Snort::drop_privileges()`, evidnetly, this function drops privileges of the process if possible.
```C++
bool Snort::drop_privileges()
{
    SnortConfig* sc = SnortConfig::get_main_conf();

    // Enter the chroot jail if necessary.
    if (!sc->chroot_dir.empty() && !EnterChroot(sc->chroot_dir, sc->log_dir))
        return false;

    // Drop privileges if requested.
    if (sc->get_uid() != -1 || sc->get_gid() != -1) // if uid or gid have been modified
    // -1 is the initialized value, meaning no change to this value
    {
        if (!SFDAQ::can_run_unprivileged())
        {
            ParseError("Cannot drop privileges - "
                "at least one of the configured DAQ modules does not support unprivileged operation.\n");
            return false;
        }
        if (!SetUidGid(sc->get_uid(), sc->get_gid()))
            return false;
    }

    privileges_dropped = true;
    return true;
}
```
The comments in above code are clear, but we need to pay attention to the chroot jail. I cannot find any official documents of the reason to use a chroot jail here, so the following statements are only my personal understanding. A chroot jail is a way to isolate a process and its children from the rest of the system. If the Snort itself is compromised, locking it inside a jail keeps malicious behaviours away from your treasure data and system files. You can, of course, achieving such operations by running Snort with `chroot(8)` utility. But Snort can also chroot itself once it is started. The implementation of `EnterChroot()` is listed below:
```C++
// Chroot and adjust the log_dir reference
bool EnterChroot(std::string& root_dir, std::string& log_dir)
{
    if (log_dir.empty())
    {
        ParseError("Log directory not specified");
        return false;
    }
    PathBuf pwd;
    PathBuf abs_log_dir;

    if ( !GetAbsolutePath(log_dir.c_str(), abs_log_dir) )
        return false;

    /* change to the desired root directory */
    if (chdir(root_dir.c_str()) != 0)
    {
        ParseError("EnterChroot: Can not chdir to \"%s\": %s", root_dir.c_str(),
            get_error(errno));
        return false;
    }

    /* always returns an absolute pathname */
    const char* abs_root_dir = CurrentWorkingDir(pwd);
    if (!abs_root_dir)
    {
        ParseError("Couldn't retrieve current working directory");
        return false;
    }
    size_t abs_root_dir_len = strlen(abs_root_dir);

    if (strncmp(abs_root_dir, abs_log_dir, abs_root_dir_len))
    {
        ParseError("Specified log directory is not contained with the chroot jail");
        return false;
    }

    if (chroot(abs_root_dir) < 0)
    {
        ParseError("Can not chroot to \"%s\": absolute: %s: %s",
            root_dir.c_str(), abs_root_dir, get_error(errno));
        return false;
    }


    /* Immediately change to the root directory of the jail. */
    if (chdir("/") < 0)
    {
        ParseError("Can not chdir to \"/\" after chroot: %s",
            get_error(errno));
        return false;
    }


    if (abs_root_dir_len >= strlen(abs_log_dir))
        log_dir = "/";
    else
        log_dir = abs_log_dir + abs_root_dir_len;


    LogMessage("Chroot directory = %s\n", root_dir.c_str());

    return true;
}
```
Someone may have questions like "when will the `drop_privileges` being invoked?". Actually, it is called at the very beginning of Snort's life-cycle (under the branch `case Analyzer::State::INITIALIZED` of the `handler()` function in main.cc). This ensures at most of the execuation time, Snort, if possible, is under a low privilege environment.