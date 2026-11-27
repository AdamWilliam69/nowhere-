usage() {
    cat << USAGEEOF
$(L '用法'): adam [$(L '命令')]          $(L '（')$(L '不带参数 = 打开主菜单')$(L '）')

$(L '主菜单'): 1 Nowhere · 2 Snell · 3 Xray · 4 $(L '脚本更新') · 5 $(L '防火墙') · 6 Fail2ban · 7 $(L '系统调优') · 8 $(L '自动维护') · 9 Realm · 10 $(L '域名反代')

Nowhere:
  $(L 'nowhere                    打开 Nowhere 菜单')
  install | uninstall | update | reconfig | config | status | logs | restart | nowhere-repair
  fingerprint | version | select-version | rollback | generate-key | probe
  cert-status | install-egress | shortcuts

Snell v${SNELL_MAJOR}:
  $(L 'snell                      打开 Snell 菜单')
  snell install | update | config | reconfig | status | health | repair | logs | restart | uninstall
  snell ports | add-port | del-port [$(L '端口')]    $(L '多端口：列出 / 新增 / 删除某个端口配置')
  snell auto on|$(L 'off          开/关 跟随官方发布的自动更新（默认 beta 通道：跟随最新测试版）')

Xray (SS / VLESS):
  $(L 'xray                       打开 Xray 菜单')
  xray install | add | edit [tag] | list | links | delete | update | health | repair | status | logs | restart | cnblock [on|off] | uninstall
  xray fwd add | list | toggle | delete | test | restart | status    $(L '端口转发') (dokodemo-door)

Realm $(L '端口转发'):
  $(L 'realm                      打开 Realm 端口转发菜单')
  realm install | add | batch | edit | list | toggle | delete | test | config | tune | auto | repair | restart | status | logs | export | import | uninstall

$(L '域名反代') (Caddy / Cloudflare Tunnel):
  $(L 'proxy                      打开域名反代菜单（Caddy / Cloudflare Tunnel）')
  $(L 'caddy / tunnel             直接操作 Caddy 反代或 Cloudflare Tunnel（均支持 repair / auto）')

$(L '系统与网络调优:')
  $(L 'tune                       打开调优菜单')
  tune tcp [$(L 'tcpfit 子命令')]   $(L '运行 tcpfit（不带子命令 = 它的菜单），如 adam tune tcp status')
  tune xanmod | xanmod-remove
  tune dns [show|set|restore] | prefer [ipv4|ipv6|restore] | ipv6 [off|off-temp|on] | status

$(L '自动维护:')
  $(L 'auto                       打开自动维护菜单（保活巡检 / 自动更新开关）')
  maintain | $(L 'watchdog        立即执行一次每日维护 / 保活巡检（定时器调用的就是这两个）')
  repair                     $(L '一键全量自检与修复所有已安装组件')
  notify                     $(L '配置运维告警推送（Telegram / Bark / Webhook）')
  export [mihomo|singbox|surge]  $(L '导出多客户端配置片段')
  $(L 'maintain-log               查看维护记录')

$(L '防火墙') (ufw):
  $(L 'fw                         打开防火墙菜单')
  fw install | list | status | on | off | sync
  $(L 'fw allow <端口>            例: adam fw allow 443/tcp,8000-8100    （不写协议 = TCP+UDP）')
  $(L 'fw deny  <端口>            删除放行规则')

Fail2ban:
  $(L 'f2b                        打开 Fail2ban 菜单')
  f2b install | status | banned | log | on | off | restart | uninstall
  $(L 'f2b bantime <时长>         例: adam f2b bantime 1h   （纯数字 = 分钟，-1 = 永久）')
  f2b ban <IP> | unban <IP> | unban-all

$(L '其他:')
  $(L 'script                     打开脚本更新菜单')
  update-script              $(L '立即更新本管理脚本')
  lang [zh|en]               $(L '切换界面语言')$(L '（zh=中文 / en=English）')
  backup [--encrypt] | restore [$(L '文件')]  $(L '备份配置') / $(L '恢复配置')
  doctor [--json]            $(L '一键诊断')
  log-cleanup                $(L '清理日志')
  migrate-tls2               tls=1 $(L '升级为真实证书') (tls=2)
USAGEEOF
}

run_interactive_menu() {
    ask_lang_first_time
    ensure_adam_shortcut || true
    while true; do
        show_menu
        case "$MENU_CHOICE" in
            1) nowhere_menu ;;
            2) snell_menu ;;
            3) xray_menu ;;
            4) script_menu ;;
            5) fw_menu ;;
            6) f2b_menu ;;
            7) tune_menu ;;
            8) maint_menu ;;
            9) realm_menu ;;
            10) proxy_menu ;;
            0) exit 0 ;;
            *) warn "$(L '无效选择')"; pause_return ;;
        esac
    done
}

case "$ACTION" in
    menu)       run_interactive_menu ;;
    install)    do_install ;;
    uninstall)  do_uninstall ;;
    update)     do_update ;;
    reconfig)   do_reconfig ;;
    config)     do_show_config ;;
    status)     do_show_status ;;
    logs)       do_show_logs ;;
    fingerprint) do_fingerprint ;;
    restart)    do_restart ;;
    nowhere-repair) nowhere_repair ;;
    shortcuts)  install_shortcuts ;;
    version)    do_show_version ;;
    select-version) do_select_version ;;
    rollback)   do_rollback ;;
    generate-key) do_genkey ;;
    probe)      do_probe "${ACTION_ARGS[@]}" ;;
    cert-status) do_cert_status ;;
    install-egress) do_install_egress_service ;;
    snell)      snell_cli "${ACTION_ARGS[@]}" ;;
    snell-autoupdate) snell_autoupdate ;;
    fw|firewall) fw_cli "${ACTION_ARGS[@]}" ;;
    f2b|fail2ban) f2b_cli "${ACTION_ARGS[@]}" ;;
    update-script) do_update_script ;;
    nowhere)    nowhere_menu ;;
    script)     script_menu ;;
    xray)       xray_cli "${ACTION_ARGS[@]}" ;;
    realm|pf)   realm_cli "${ACTION_ARGS[@]}" ;;
    proxy|caddy) proxy_cli "${ACTION_ARGS[@]}" ;;
    tunnel)     cf_tunnel_cli "${ACTION_ARGS[@]}" ;;
    tune)       tune_cli "${ACTION_ARGS[@]}" ;;
    auto|maint) maint_menu ;;
    watchdog)   maint_watchdog ;;
    maintain)   maint_daily ;;
    maintain-log) maint_show_log ;;
    repair)     do_repair_all ;;
    notify)     notify_menu ;;
    export)     do_export_clients "${ACTION_ARGS[0]:-}" ;;
    lang)       set_lang "${ACTION_ARGS[0]:-}" ;;
    backup)     do_backup "${ACTION_ARGS[@]}" ;;
    restore)    do_restore "${ACTION_ARGS[0]:-}" ;;
    doctor)     do_doctor "${ACTION_ARGS[@]}" ;;
    log-cleanup) do_log_cleanup ;;
    migrate-tls2) do_migrate_tls2 ;;
    help|-h|--help) usage ;;
    *) usage; error "$(L '未知操作:') ${ACTION}" ;;
esac
