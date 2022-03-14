# Problem Set 1

In the first part of this problem set, you'll implement Lamport signatures. In the second part, you'll take advantage of incorrect usage to forge signatures.

## Testing and Timeouts

To run tests,

```
$ go test
```

will work, but by default it will give up after 10 minutes. If your functions need more time to complete, you can change the timeout by typing

```
$ go test -timeout 30m
```

to timeout after 30 minutes instead of 10.
