# bash completion for netwatch
#
# Kept in step with src/cli.rs by `completions_and_man_cover_every_option`
# in that file: adding an option there fails the test until it is listed
# here too.
#
# Install: source this file, or drop it in /etc/bash_completion.d/ (the
# .deb and .rpm packages do that for you).

_netwatch() {
    local cur prev words cword
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local subcommands="daemon doctor diagnose uptime geoip resolver"
    local options="--remote --api-key --insecure-remote --view --lite --demo \
        --no-sandbox --sandbox-strict --metrics --metrics-addr --daemon \
        --headless --generate-config --help -h --version -V"

    # Options that take a value: complete the value, not another flag.
    case "${prev}" in
        --view)
            COMPREPLY=( $(compgen -W "full lite dense" -- "${cur}") )
            return 0
            ;;
        --interface)
            local ifaces
            ifaces=$(ls /sys/class/net 2>/dev/null)
            COMPREPLY=( $(compgen -W "${ifaces}" -- "${cur}") )
            return 0
            ;;
        --remote|--api-key|--metrics-addr|--seconds|--out|--schema|--since)
            return 0
            ;;
    esac

    # Subcommand-specific completions.
    case "${COMP_WORDS[1]}" in
        doctor)
            COMPREPLY=( $(compgen -W "--json --check-capture --interface" -- "${cur}") )
            return 0
            ;;
        diagnose)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "run coverage episodes replay features export corpus" -- "${cur}") )
            else
                COMPREPLY=( $(compgen -W "--json --seconds --test --out --schema --since --dry-run --target --budget --format --only --include-beta --unstable" -- "${cur}") )
            fi
            return 0
            ;;
        uptime)
            COMPREPLY=( $(compgen -W "--since --json --csv" -- "${cur}") )
            return 0
            ;;
        geoip)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "update" -- "${cur}") )
            else
                COMPREPLY=( $(compgen -W "--city" -- "${cur}") )
            fi
            return 0
            ;;
        resolver)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "status set recover" -- "${cur}") )
            else
                COMPREPLY=( $(compgen -W "--unmanaged --seconds" -- "${cur}") )
            fi
            return 0
            ;;
    esac

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${options}" -- "${cur}") )
    else
        COMPREPLY=( $(compgen -W "${subcommands} ${options}" -- "${cur}") )
    fi
}

complete -F _netwatch netwatch
