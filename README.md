# HiddenNtRegistry
Use NT Native Registry API to create a registry that normal user can not query.

Author: 3gstudent

**Notes:**

Refer to Daniel Madden Sr's NtRegistry.

Link: https://www.codeproject.com/Articles/14508/Registry-Manipulation-Using-NT-Native-APIs

Rewrite the CNtRegistry class.

Add the following functions:

- Create hidden key value
- Read hidden key value
- Delete hidden key value

**Principle:**

```
“In the Win32 API strings are interpreted as NULL-terminated ANSI (8-bit) or wide character (16-bit) strings. In the Native API names are counted Unicode (16-bit) strings. While this distinction is usually not important, it leaves open an interesting situation: there is a class of names that can be referenced using the Native API, but that cannot be described using the Win32 API. […] When a key (or any other object with a name such as a named Event, Semaphore or Mutex) is created with such a name any applications using the Win32 API will be unable to open the name, even though they might seem to see it.”
```

More explanation: https://www.symantec.com/connect/blogs/kovter-malware-learns-poweliks-persistent-fileless-registry-update
