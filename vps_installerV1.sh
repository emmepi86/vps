#!/usr/bin/env bash
###############################################################################
# HARDENING SERVER LINUX – SCRIPT COMPLETO (10 BLOCCHI MODULARI)              #
# Autore: <tuo‑nome>                                                          #
###############################################################################

################################################################################
# 0) VARIABILI GLOBALI, LOGGING, DRY‑RUN                                        #
################################################################################
SCRIPT_NAME=$(basename "$0")
LOG_DIR=/var/log/hardening
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/hardening_${TIMESTAMP}.log"
EMAIL_REPORT="admin@example.com"

DRY_RUN=false
VERBOSE=false

# ── directory e file di log ───────────────────────────────────────────────────
mkdir -p "$LOG_DIR" && chmod 700 "$LOG_DIR"
touch "$LOG_FILE"     && chmod 600 "$LOG_FILE"

# ── funzioni di log ───────────────────────────────────────────────────────────
log()  { echo -e "[$(date +'%F %T')] [$1] $2" | tee -a "$LOG_FILE" ; }
info() { log INFO  "$1"; }
warn() { log WARN  "$1"; }
err()  { log ERROR "$1"; }

# ── funzione run (rispetta il dry‑run) ────────────────────────────────────────
run()  { info "Eseguo: $*"; $DRY_RUN && info "[DRY‑RUN] Skipped" || eval "$*"; }

# ── redirezione stdout/stderr al file di log ──────────────────────────────────
exec > >(tee -a "$LOG_FILE") 2>&1

################################################################################
# 0b) PARSER OPZIONI                                                           #
################################################################################
usage() {
  cat <<EOF
Uso: $SCRIPT_NAME [opzioni] [blocchi]
  -n, --dry-run    Simula il flusso senza applicare modifiche
  -v, --verbose    Output a video più dettagliato
  -h, --help       Mostra questa guida
Blocchi disponibili: 1–10   (es. 1 4 8-10)
EOF
  exit 0
}

OPTS=$(getopt -o nvh -l dry-run,verbose,help -- "$@") || usage
eval set -- "$OPTS"
while true; do
  case "$1" in
    -n|--dry-run) DRY_RUN=true ; shift ;;
    -v|--verbose) VERBOSE=true ; shift ;;
    -h|--help)    usage ;;
    --) shift; break ;;
  esac
done
BLOCCHI=("$@")

################################################################################
# 0c) FUNZIONI UTILI                                                           #
################################################################################
banner()  { echo -e "\n================ $* ================\n"; }
launch()  { local n=$1; banner "INIZIO BLOCCO $n"; bash "$0" "__blocco__$n"; banner "FINE BLOCCO $n"; }

################################################################################
# 0d) ENTRY‑POINT (MENU / SELEZIONE BLOCCHI)                                   #
################################################################################
if [[ $1 != __blocco__* ]]; then
  # se non sono stati passati blocchi su CLI → mostra menu
  if [ ${#BLOCCHI[@]} -eq 0 ]; then
    banner "HARDENING MENU"
    printf " 1) SSH\t\t 2) UFW\t\t 3) AppArmor+ClamAV+GRUB\n"
    printf " 4) Web+ModSec\t 5) Fail2Ban\t 6) rkhunter+unatt\n"
    printf " 7) Backup\t 8) Hardening avanzato\n"
    printf " 9) Monitoraggio+Docker+Ansible\n"
    printf "10) 🔐 Ultra Hardening\n"
    read -rp "Blocchi da eseguire (es. 1 4 8‑10): " -a BLOCCHI
  fi
  # esecuzione sequenziale dei blocchi richiesti
  for b in "${BLOCCHI[@]}"; do
    [[ $b =~ ^([1-9]|10)$ ]] && launch "$b" || warn "❌ Blocco $b non valido"
  done

  # ── verifica post‑hardening ────────────────────────────────────────────────
  banner "VERIFICA POST‑HARDENING"
  run "awk -F: '\$3>=1000 && \$7 !~/nologin|false/ {print \"Utente: \"\$1\" → \"\$7}' /etc/passwd"
  run "ss -tulnp | grep LISTEN"
  run "find / -perm /6000 -type f -print 2>/dev/null | tail -n 10"
  run "df -hT | awk 'NR==1||/\\/dev\\//{print}'"

  # ── invio report e‑mail (se mailx presente) ───────────────────────────────
  if command -v mail >/dev/null 2>&1; then
    run "mail -s '[HARDENING] $(hostname) $TIMESTAMP' $EMAIL_REPORT < $LOG_FILE"
  else
    warn "Comando mailx non installato: report non inviato"
  fi

  info "✨ Fine script. Log completo in $LOG_FILE"
  exit 0
fi

###############################################################################
# BLOCCO 1 – CONFIGURAZIONE SSH                                               #
###############################################################################
if [[ $1 == __blocco__1 ]]; then
  run "cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak"
  grep -q '^Port 48484' /etc/ssh/sshd_config || run "cat > /etc/ssh/sshd_config <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
Port 48484
LoginGraceTime 30
PermitRootLogin no
MaxAuthTries 4
MaxSessions 10
DisableForwarding yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PermitUserEnvironment no
ClientAliveInterval 15
ClientAliveCountMax 3
MaxStartups 10:30:60
PermitTunnel no
DebianBanner no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF"
  run "systemctl restart sshd"
  exit 0
fi

###############################################################################
# BLOCCO 2 – CONFIGURAZIONE UFW                                               #
###############################################################################
if [[ $1 == __blocco__2 ]]; then
  run "ufw --force reset"
  for pol in incoming outgoing routed; do run "ufw default deny $pol"; done
  for rule in "allow in on lo" "allow out on lo"; do run "ufw $rule"; done
  for p in 53/udp 53/tcp 80/tcp 443/tcp; do run "ufw allow out to any port ${p%%/*} proto ${p##*/}"; done
  run "ufw allow out proto icmp"; run "ufw allow in proto icmp"
  run "ufw allow out to any port 123 proto udp"
  for p in 48484 80 443; do run "ufw allow $p/tcp"; done
  run "ufw deny in from 127.0.0.0/8"
  run "ufw deny in from ::1"
  run "ufw --force enable"
  exit 0
fi

###############################################################################
# BLOCCO 3 – APPARMOR · CLAMAV · GRUB                                         #
###############################################################################
if [[ $1 == __blocco__3 ]]; then
  run "apt-get update"
  run "apt-get install -y apparmor apparmor-utils clamav clamav-daemon"
  grep -q apparmor=1 /etc/default/grub || run "sed -i 's|^GRUB_CMDLINE_LINUX=\"\\(.*\\)\"|GRUB_CMDLINE_LINUX=\"\\1 apparmor=1 security=apparmor\"|' /etc/default/grub"
  run "update-grub"
  run "aa-complain /etc/apparmor.d/*"
  run "aa-enforce  /etc/apparmor.d/usr.*"
  run "chown root:root /boot/grub/grub.cfg && chmod 600 /boot/grub/grub.cfg"
  run "sysctl -w kernel.randomize_va_space=2"
  run "freshclam"
  run "systemctl enable --now clamav-freshclam.service"
  warn "👉 Riavvio consigliato per applicare AppArmor al 100 %"
  exit 0
fi

###############################################################################
# BLOCCO 4 – WEB SERVER + MODSECURITY                                         #
###############################################################################
if [[ $1 == __blocco__4 ]]; then
  read -rp "Web server [apache|nginx] (default apache): " WS
  WS=${WS,,}; WS=${WS:-apache}
  run "apt-get update"

  if [[ $WS == nginx ]]; then
    # ── NGINX + ModSecurity v3 ───────────────────────────────────────────────
    info "Installazione Nginx + ModSecurity3"
    run "apt-get install -y nginx mysql-server php-fpm php-mysql git gcc make build-essential autoconf automake libtool pkg-config libpcre2-dev zlib1g-dev libyajl-dev libgeoip-dev liblua5.3-dev"

    run "systemctl enable --now nginx mysql"
    run "ufw allow 'Nginx HTTP'"; run "ufw allow 'Nginx HTTPS'"
    run "mysql_secure_installation"

    # attiva PHP‑FPM sul virtual host di default
    DEF=/etc/nginx/sites-available/default
    grep -q index.php "$DEF" || run "sed -i 's/index.nginx-debian.html/index.php index.html index.htm index.nginx-debian.html/' $DEF"
    run "sed -i '/location ~ \\\\.php$ {/,/}/ s/#//g' $DEF"

    # ── libreria ModSecurity ────────────────────────────────────────────────
    run "git clone https://github.com/SpiderLabs/ModSecurity.git /opt/ModSecurity"
    run "cd /opt/ModSecurity && git submodule update --init --recursive && ./build.sh && ./configure && make && make install"

    # ── modulo ModSecurity‑nginx dinamico ───────────────────────────────────
    run "git clone https://github.com/SpiderLabs/ModSecurity-nginx.git /opt/ModSecurity-nginx"
    VER=$(nginx -v 2>&1 | grep -o '[0-9.]*')
    run "wget -q https://nginx.org/download/nginx-${VER}.tar.gz -O /tmp/nginx.tar.gz"
    run "tar -xzf /tmp/nginx.tar.gz -C /tmp"
    run "cd /tmp/nginx-${VER} && ./configure --with-compat --add-dynamic-module=/opt/ModSecurity-nginx && make modules"
    run "cp /tmp/nginx-${VER}/objs/ngx_http_modsecurity_module.so /etc/nginx/modules-enabled/"

    # ── file di configurazione ModSecurity per Nginx ────────────────────────
    run "cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf"
    run "cp /opt/ModSecurity/unicode.mapping /etc/nginx/unicode.mapping"
    run "sed -i 's/SecRuleEngine.*/SecRuleEngine On/' /etc/nginx/modsecurity.conf"

    # carica il modulo nel main nginx.conf
    grep -q ngx_http_modsecurity_module /etc/nginx/nginx.conf ||
      run "sed -i '1iload_module /etc/nginx/modules-enabled/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf"

    # abilita modsecurity sul vhost default
    grep -q 'modsecurity on;' "$DEF" ||
      run "sed -i '/server_name _;/a \\tmodsecurity on;\\n\\tmodsecurity_rules_file /etc/nginx/modsecurity.conf;' $DEF"

    # OWASP CRS
    run "git clone https://github.com/coreruleset/coreruleset.git /etc/nginx/owasp-crs"
    grep -q crs-setup.conf /etc/nginx/modsecurity.conf ||
      run "cat >> /etc/nginx/modsecurity.conf <<'EOC'
Include /etc/nginx/owasp-crs/crs-setup.conf
Include /etc/nginx/owasp-crs/rules/*.conf
EOC"

    run "nginx -t"
    run "systemctl restart nginx"
    info "✅ Nginx + ModSecurity3 installati"

  else
    # ── APACHE + ModSecurity v2 ─────────────────────────────────────────────
    info "Installazione Apache + ModSecurity2"
    run "apt-get install -y apache2 mysql-server php php-mysql libapache2-mod-security2 git"
    run "systemctl enable --now apache2 mysql"
    run "ufw allow 'Apache Full'"
    run "mysql_secure_installation"

    # abilita ModSecurity
    run "a2enmod security2 headers"
    run "sed -i 's/^SecRuleEngine.*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf"

    CRS=/etc/modsecurity/owasp-crs
    [[ -d $CRS ]] || run "git clone https://github.com/coreruleset/coreruleset.git $CRS"
    [[ -f $CRS/crs-setup.conf ]] || run "cp $CRS/crs-setup.conf.example $CRS/crs-setup.conf"

    SEC2=/etc/apache2/mods-enabled/security2.conf
    grep -q crs-setup.conf $SEC2 || run "echo 'Include $CRS/crs-setup.conf' >> $SEC2"
    grep -q 'rules/*.conf'  $SEC2 || run "echo 'Include $CRS/rules/*.conf'   >> $SEC2"

    run "apachectl configtest"
    run "systemctl restart apache2"
    info "✅ Apache + ModSecurity2 installati"
  fi
  exit 0
fi

###############################################################################
# BLOCCO 5 – FAIL2BAN                                                         #
###############################################################################
if [[ $1 == __blocco__5 ]]; then
  run "apt-get update"
  run "apt-get install -y fail2ban"
  read -rp "IP da ignorare (separati da spazio, vuoto = nessuno extra): " IPS
  IPS="${IPS:-}"; IGNORE="127.0.0.1/8 ::1 ${IPS}"
  run "cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = ${IGNORE}
bantime  = 8h
findtime = 10m
maxretry = 3

[sshd]
enabled  = true
port     = 48484
filter   = sshd
logpath  = /var/log/auth.log
EOF"
  run "systemctl enable --now fail2ban"
  info "✅ Fail2Ban configurato"
  exit 0
fi

###############################################################################
# BLOCCO 6 – RKHUNTER + UNATTENDED‑UPGRADES                                   #
###############################################################################
if [[ $1 == __blocco__6 ]]; then
  run "apt-get update"
  run "apt-get install -y rkhunter unattended-upgrades"
  run "rkhunter --update"
  run "rkhunter --propupd"
  run "dpkg-reconfigure -plow unattended-upgrades"
  info "✅ rkhunter & unattended‑upgrades configurati"
  exit 0
fi

###############################################################################
# BLOCCO 7 – BACKUP LOCALI (www + MySQL)                                      #
###############################################################################
if [[ $1 == __blocco__7 ]]; then
  run "mkdir -p /home/backupvarwww/{www,monthly} /home/backup-db"

  read -rp "MySQL user [dna]: "   DBU; DBU=${DBU:-dna}
  read -rp "MySQL password [mysqlpassword]: " DBP; DBP=${DBP:-mysqlpassword}
  read -rp "MySQL host [localhost]: " DBH; DBH=${DBH:-localhost}

  MYC="/home/$USER/.my.cnf"
  run "cat > $MYC <<EOF
[client]
user=${DBU}
password=\"${DBP}\"
host=${DBH}
EOF"
  run "chmod 600 $MYC"

  run "cat > /etc/cron.d/backupjobs <<'EOC'
# backup www
10 23 * * * root rsync -rhzu /var/www /home/backupvarwww/ >> /var/log/wwwbackup.log 2>&1
10 22 14 * * * root rsync -vrhzuaAp /var/www /home/backupvarwww/monthly >> /var/log/wwwmonthlybackup.log 2>&1
0 2 * * * root tar -czf /home/backupvarwww/www\$(date +\\%F).tar.gz /home/backupvarwww/www
30 2 * * * root find /home/backupvarwww/ -type f -name '*.gz' -mtime +10 -delete
# dump MySQL
0 23 * * * root mysqldump --defaults-file=$MYC --all-databases | gzip > /home/backup-db/db_\$(date +\\%Y\\%m\\%d).sql.gz
0 22 * * * root find /home/backup-db/ -type f -name '*.sql.gz' -mtime +30 -delete
EOC"
  info "✅ Cron di backup locali configurato"
  exit 0
fi

###############################################################################
# BLOCCO 8 – HARDENING AVANZATO                                               #
###############################################################################
if [[ $1 == __blocco__8 ]]; then
  # HTTP security headers (solo se Apache presente)
  if [[ -d /etc/apache2 ]]; then
    run "a2enmod headers"
    run "cat > /etc/apache2/conf-available/security-headers.conf <<'EOH'
<IfModule mod_headers.c>
Header always set X-Frame-Options \"SAMEORIGIN\"
Header always set X-XSS-Protection \"1; mode=block\"
Header always set X-Content-Type-Options \"nosniff\"
Header always set Referrer-Policy \"strict-origin-when-cross-origin\"
Header always set Content-Security-Policy \"default-src 'self';\"
Header always set Permissions-Policy \"geolocation=(), microphone=()\"
</IfModule>
EOH"
    run "a2enconf security-headers.conf"
    run "systemctl restart apache2"
  fi

  # auditd
  run "apt-get install -y auditd audispd-plugins"
  run "systemctl enable --now auditd"

  # AIDE (integrità file)
  run "apt-get install -y aide"
  run "aideinit"
  run "cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
  run "echo '0 3 * * * root /usr/bin/aide --check' > /etc/cron.d/aide-check"

  # logrotate per log di backup
  run "cat > /etc/logrotate.d/wwwbackup <<'EOL'
/var/log/wwwbackup.log /var/log/wwwmonthlybackup.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 640 root adm
}
EOL"
  info "✅ Hardening avanzato completato"
  exit 0
fi

###############################################################################
# BLOCCO 9 – MONITORAGGIO (Wazuh/OSSEC/Elastic) · DOCKER · ANSIBLE            #
###############################################################################
if [[ $1 == __blocco__9 ]]; then
  read -rp "Agente SIEM [wazuh|ossec|elastic] (default wazuh): " SIEM
  SIEM=${SIEM,,}; SIEM=${SIEM:-wazuh}

  if [[ $SIEM == wazuh ]]; then
    run "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg"
    run "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main' > /etc/apt/sources.list.d/wazuh.list"
    run "apt-get update"
    run "apt-get install -y wazuh-agent"
    read -rp "IP server Wazuh: " WIP
    run "sed -i 's|<address>.*</address>|<address>${WIP}</address>|' /var/ossec/etc/ossec.conf"
    run "systemctl enable --now wazuh-agent"
  elif [[ $SIEM == ossec ]]; then
    run "apt-get install -y build-essential inotify-tools zlib1g-dev libssl-dev"
    run "curl -L -o /tmp/ossec.tar.gz https://github.com/ossec/ossec-hids/archive/refs/tags/3.7.0.tar.gz"
    run "tar -xzf /tmp/ossec.tar.gz -C /tmp"
    run "cd /tmp/ossec-hids-* && ./install.sh"
  else
    VER="8.12.2"
    run "curl -L -o /tmp/elastic-agent.tar.gz https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${VER}-linux-x86_64.tar.gz"
    run "tar -xzf /tmp/elastic-agent.tar.gz -C /tmp"
    warn "⚠️  Ricordati di sostituire URL e token prima di installare l'Elastic Agent"
  fi

  # ── Docker (con hardening daemon.json) ─────────────────────────────────────
  run "apt-get install -y apt-transport-https ca-certificates curl software-properties-common"
  run "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg"
  run "echo 'deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable' > /etc/apt/sources.list.d/docker.list"
  run "apt-get update"
  run "apt-get install -y docker-ce docker-ce-cli containerd.io"
  run "mkdir -p /etc/docker"
  run "cat > /etc/docker/daemon.json <<'EOD'
{
  \"icc\": false,
  \"no-new-privileges\": true,
  \"userns-remap\": \"default\",
  \"live-restore\": true,
  \"log-driver\": \"json-file\",
  \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}
}
EOD"
  run "systemctl enable --now docker"
  run "usermod -aG docker $USER"

  # ── Ansible + playbook demo ────────────────────────────────────────────────
  run "apt-get install -y ansible"
  run "mkdir -p ~/ansible/playbooks"
  run "cat > ~/ansible/playbooks/hardening.yml <<'EOP'
---
- hosts: all
  become: true
  tasks:
    - name: Disabilita root login via SSH
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
EOP"
  info "✅ Monitoraggio, Docker e Ansible configurati"
  exit 0
fi

###############################################################################
# BLOCCO 10 – 🔐 ULTRA HARDENING                                              #
###############################################################################
if [[ $1 == __blocco__10 ]]; then
  # ── sysctl avanzato ────────────────────────────────────────────────────────
  run "cat >> /etc/sysctl.conf <<'EOS'
# —— Ultra Hardening ————————————————————————
net.ipv4.conf.all.rp_filter          = 1
net.ipv4.conf.default.rp_filter      = 1
net.ipv4.tcp_syncookies              = 1
net.ipv4.conf.all.accept_redirects   = 0
net.ipv6.conf.all.accept_redirects   = 0
net.ipv4.conf.all.accept_source_route= 0
net.ipv6.conf.all.accept_source_route= 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.send_redirects     = 0
net.ipv4.ip_forward                  = 0
net.ipv6.conf.all.disable_ipv6       = 1
EOS"
  run "sysctl -p"

  # ── kernel params via GRUB ────────────────────────────────────────────────
  run "sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"slab_nomerge pti=on page_poison=1 vsyscall=none kptr_restrict=2 quiet loglevel=0 /' /etc/default/grub"
  run "update-grub"

  # ── disabilita login utenti di sistema (<1000) ───────────────────────────
  for u in $(awk -F: '$3 < 1000 {print $1}' /etc/passwd); do run "usermod -s /usr/sbin/nologin $u"; done

  # ── banner legale ─────────────────────────────────────────────────────────
  run "echo 'Accesso non autorizzato è vietato. Tutte le attività verranno registrate.' > /etc/issue.net"
  run "sed -i 's|#Banner none|Banner /etc/issue.net|' /etc/ssh/sshd_config"
  run "systemctl restart sshd"

  # ── restrizioni cron / at ────────────────────────────────────────────────
  run "echo root > /etc/cron.allow"
  run "echo root > /etc/at.allow"
  run "rm -f /etc/cron.deny /etc/at.deny"

  # ── mount tmpfs sicuri ───────────────────────────────────────────────────
  grep -q '^tmpfs /tmp' /etc/fstab || run "cat >> /etc/fstab <<'EOT'
tmpfs /tmp     tmpfs defaults,noexec,nosuid,nodev 0 0
tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0
tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0
EOT"

  # ── audit SUID/SGID ──────────────────────────────────────────────────────
  run "find / -perm /6000 -type f -exec ls -lh {} \\; 2>/dev/null | tee /var/log/suid_audit.log"

  # ── journald persistente ────────────────────────────────────────────────
  run "mkdir -p /var/log/journal"
  run "sed -i 's/#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf"
  run "systemctl restart systemd-journald"

  # ── hardening shell utente ───────────────────────────────────────────────
  run "cat >> /etc/profile <<'EOP'
set -o noclobber
export HISTCONTROL=ignoredups:erasedups
export HISTFILESIZE=5000
export HISTSIZE=5000
export HISTTIMEFORMAT=\"%d/%m/%y %T \"
EOP"
  info "✅ Ultra Hardening completato – riavvio consigliato"
  exit 0
fi
