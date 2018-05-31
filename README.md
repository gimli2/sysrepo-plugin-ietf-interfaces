## Sysrepo plugin for interface management

This repository houses a [sysrepo](https://github.com/sysrepo/sysrepo) plugin
which implements (parts of the) [A YANG Data Model for Interface Management ](https://tools.ietf.org/html/rfc7223).

You'll need the ``sysrepo-plugind`` in order to make this work.

### Installation

Build and install ``sysrepo`` and then use a standard CMake setup for this.

When loading and installing modules to sysrepo, e.g.:

 sysrepoctl --install --yang ietf-ipv6-unicast-routing\@2018-03-21.yang

pay attention to proper version of required modules, especially ietf-interfaces is working only with revision 2017-12-16. If you have another revision in your datastore you should uninstall it.
