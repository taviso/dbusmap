This is a simple utility for enumerating D-Bus endpoints, an nmap for D-Bus.

The problem with auditing D-Bus services is that while endpoint names and the
policy for well-known name ownership is easily discoverable, it's less easy to
enumerate the methods and properties they export.

Endpoints are expected to allow introspection (although unfortunately it's not
enforced that the introspection be complete), but it's laborious and
complicated to do this because it requires drilling-down through object
path heirarchies.

This is a tool that automates that, and allows some simple filtering and
probing. It is intended to help make D-Bus services more discoverable by system
administrators and security researchers, analagous to the `netstat` or `find /
-perm -u+s` you might currently use to probe your attack surface.

# Usage

By default, dbus-map lists all the clients on the system bus and tries to map
them to processes.

```
$ dbus-map
PID                 USER                                        NAME                             CMDLINE
-1               unknown                        org.freedesktop.DBus                                    
12975               root                      org.freedesktop.login1         /lib/systemd/systemd-logind
29264               root                 com.ubuntu.LanguageSelector                    /usr/bin/python3 /usr/lib/language-selector/ls-dbus-backend
29268               root                       com.ubuntu.USBCreator                    /usr/bin/python3 /usr/share/usb-creator/usb-creator-helper
4548                root                                com.hp.hplip                     /usr/bin/python /usr/bin/hp-pkservice
5634              colord                org.freedesktop.ColorManager              /usr/lib/colord/colord
...
```

The name will either be it's well known name, or if it begines with ':' that's
a unique name assigned by dbus. If a well-known name is unprotected and you have
enabled probes (see below), a ! appears after the name. This means that you
have permission to take over the name.

(Note: Unprotected is not necessarily bad, you might be an Active Administrator or it might be by design)

To dump all the exposed methods, use --dump-methods, it will print them
prefixed with m:, followed by the instance and method name and then the object
path.

```
$ dbus-map --dump-methods
PID             USER                                        NAME                             CMDLINE
-1           unknown                        org.freedesktop.DBus                                    
    m:org.freedesktop.DBus.Hello /
    m:org.freedesktop.DBus.RequestName /
    m:org.freedesktop.DBus.ReleaseName /
    m:org.freedesktop.DBus.StartServiceByName /
    m:org.freedesktop.DBus.UpdateActivationEnvironment /
    m:org.freedesktop.DBus.NameHasOwner /
    m:org.freedesktop.DBus.ListNames /
    m:org.freedesktop.DBus.ListActivatableNames /
    m:org.freedesktop.DBus.AddMatch /
    m:org.freedesktop.DBus.RemoveMatch /
    m:org.freedesktop.DBus.GetNameOwner /
    m:org.freedesktop.DBus.ListQueuedOwners /
    m:org.freedesktop.DBus.GetConnectionUnixUser /
    m:org.freedesktop.DBus.GetConnectionUnixProcessID /
    m:org.freedesktop.DBus.GetAdtAuditSessionData /
    m:org.freedesktop.DBus.GetConnectionSELinuxSecurityContext /
    m:org.freedesktop.DBus.GetConnectionAppArmorSecurityContext /
    m:org.freedesktop.DBus.ReloadConfig /
    m:org.freedesktop.DBus.GetId /
    m:org.freedesktop.DBus.Introspectable.Introspect /
12975               root                      org.freedesktop.login1         /lib/systemd/systemd-logind
    m:org.freedesktop.login1.Manager.GetSession /org/freedesktop/login1
    m:org.freedesktop.login1.Manager.GetSessionByPID /org/freedesktop/login1
    m:org.freedesktop.login1.Manager.GetUser /org/freedesktop/login1
    m:org.freedesktop.login1.Manager.GetSeat /org/freedesktop/login1
```

There's no guarantee that an endpoint uses PolicyKit actions consistently or
even correctly, so dbus-map can probe methods and properties to see what is
permitted. It does this by setting properties to their current values and
checking for an error.

For Methods, dbus-map calls them with invalid parameters and checks what error
was returned. If the error indicates access was denied, it's assumed it's
protected by a polkit action. If the call was rejected because of invalid
parameters, it probably is not.

To probe methods use --enable-probes, and only properties and methods that
dbus-map thinks you have access to will be displayed. However, be aware this
might generate lots of polkit-agent activity (i.e. authentication prompts).

If you want, dbus-map can automatically cancel all authentication attempts, as
if you had hit Escape. This is achieved by registering itself as it's own null
authentication agent.

It is not currently possible for dbus-map to automate successful
authentication, as that requires root (or invoking polkit-agent-helper-1). In
future, it might be possible to authenticate once, and dbus-map will keep
invoking polkit-agent-helper-1 for you, but this is not currently implemented.

```
$ dbus-map --dump-methods --enable-probes --null-agent
```

Now only methods that you can invoke should be listed. This also works with
properties, which are prefixed with p:

```
$ dbus-map --dump-methods --dump-properties --enable-probes --null-agent
```

To call a method or set a property you have discovered, use the standard
utility dbus-send.

# PolicyKit

The standard way of authenticating D-Bus methods is with PolicyKit actions. If
you want to list all the PolicyKit actions available, you can use the standard
tool pkaction.

```
$ pkaction 
com.canonical.controlcenter.datetime.configure
com.canonical.controlcenter.user-accounts.administration
com.canonical.indicator.sound.AccountsService.ModifyAnyUser
com.canonical.indicator.sound.AccountsService.ModifyOwnUser
...
```

This doesn't allow any sort of filtering though (for example, dump all
actions permitted by inactive (remote) users without authentication), so
I've added basic support for this.

This is currently very basic, e.g.

```
$ dbus-map --dump-actions=inactive=yes,any=yes
Action                                                           Any/Inactive/Active
org.freedesktop.login1.inhibit-handle-power-key                  No/Yes/Yes
org.freedesktop.NetworkManager.network-control                   No/Yes/Yes
com.ubuntu.systemservice.getkeyboard                             No/Yes/Yes
com.canonical.indicator.sound.AccountsService.ModifyOwnUser      Yes/Yes/Yes
```

# PolicyKit/D-Bus Glossary

A quick primer on PolicyKit/D-Bus terminology.

| Term            | Description
| --------------- | ----------------
| Method          | Analagous to an RPC.
| Well-Known Name | D-Bus services might listen on a reserved name, analagous to a reserved tcp port.
| Unique Name     | All clients have a unique name, similar to an ip address.
| Action          | Name of a privilege that you may or may not be granted (like com.filesystem.mount)
| Active          | If you are physically sitting at a console, then you are an Active user.
| Inactive        | If you are remote (e.g. ssh), then you are inactive.
| Administrator   | Defined by your distribution, but usually means group membership (e.g. adm or wheel).

You can find out if you are Active like this:

```
$ cat /proc/self/cgroup 
11:hugetlb:/user/1000.user/c4.session
...
```

Then search for that session in /run/systemd

```
$ grep ACTIVE /run/systemd/sessions/c4
ACTIVE=1
```

# Build Requirements

* libxml2
* libprocps
* libglib2


# Build Intrustions

Just run make, I think this is enough to install dependencies:

```
$ sudo apt-get install libxml2-dev libprocps-dev glib2.0-dev
```


