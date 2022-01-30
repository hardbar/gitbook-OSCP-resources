# ldapsearch

## Finding user accounts

Using ldapsearch:

```
ldapsearch -h 10.99.99.101 -x -b "dc=testdomain,dc=local" '(objectClass=User)'
ldapsearch -h 10.99.99.101 -x -b "dc=testdomain,dc=local" '(objectClass=Person)'
ldapsearch -h 10.99.99.101 -x -b "dc=testdomain,dc=local" '(sAMAccountType=805306368)'
```

Using windapsearch:

```
windapsearch.py --dc-ip 10.99.99.101 -U
```

> NOTE: It's also worth searching for any "Service Accounts" as these may also have the flag set, for example:
>
> ldapsearch -h 10.99.99.101 -x -b "dc=testdomain,dc=local" | grep "Service "
>
> There is a space after "Service ", otherwise you'll get a lot of results for "Services".
