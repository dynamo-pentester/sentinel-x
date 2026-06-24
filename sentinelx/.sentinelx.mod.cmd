savedcmd_sentinelx.mod := printf '%s\n'   sentinelx.o | awk '!x[$$0]++ { print("./"$$0) }' > sentinelx.mod
