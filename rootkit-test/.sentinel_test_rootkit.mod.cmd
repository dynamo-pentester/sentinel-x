savedcmd_sentinel_test_rootkit.mod := printf '%s\n'   sentinel_test_rootkit.o | awk '!x[$$0]++ { print("./"$$0) }' > sentinel_test_rootkit.mod
