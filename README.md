# fuzzyfs

stackable case-insensitive FUSE file system

```bash
$ fuzzyfs /mnt/data /var/www/htdocs
```

This branch includes Ardil's memoization of the filename-case search.

The current plan is to move the whole thing to file descriptors, so this will soon be irrelevant. However, it might prove useful to someone else, who knows.
