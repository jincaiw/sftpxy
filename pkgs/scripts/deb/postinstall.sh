#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  # Add user and group
  if ! getent group SFTPxy >/dev/null; then
    groupadd --system SFTPxy
  fi
  if ! getent passwd SFTPxy >/dev/null; then
    useradd --system \
      --gid SFTPxy \
      --no-create-home \
      --home-dir /var/lib/SFTPxy \
      --shell /usr/sbin/nologin \
      --comment "SFTPxy user" \
      SFTPxy
  fi

  if [ -z "$2" ]; then
    # if configure has no args this is the first installation
    # for upgrades the second arg is the previously installed version
    #
    # initialize data provider
    SFTPxy initprovider -c /etc/SFTPxy
    # ensure files and folders have the appropriate permissions
    chown -R SFTPxy:SFTPxy /etc/SFTPxy /var/lib/SFTPxy /srv/SFTPxy
    chmod 750 /etc/SFTPxy /etc/SFTPxy/env.d /var/lib/SFTPxy /srv/SFTPxy
    chmod 640 /etc/SFTPxy/SFTPxy.json
  fi

  # we added /etc/SFTPxy/env.d in v2.4.0, we should check if we are upgrading
  # from a previous version but a non-recursive chmod/chown shouldn't hurt
  if [ -d /etc/SFTPxy/env.d ]; then
    chown SFTPxy:SFTPxy /etc/SFTPxy/env.d
    chmod 750 /etc/SFTPxy/env.d
  fi

  # set the cap_net_bind_service capability so the service can bind to privileged ports
  setcap cap_net_bind_service=+ep /usr/bin/SFTPxy || true

fi

if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
	# This will only remove masks created by d-s-h on package removal.
	deb-systemd-helper unmask 'SFTPxy.service' >/dev/null || true

	# was-enabled defaults to true, so new installations run enable.
	if deb-systemd-helper --quiet was-enabled 'SFTPxy.service'; then
		# Enables the unit on first installation, creates new
		# symlinks on upgrades if the unit file has changed.
		deb-systemd-helper enable 'SFTPxy.service' >/dev/null || true
	else
		# Update the statefile to add new symlinks (if any), which need to be
		# cleaned up on purge. Also remove old symlinks.
		deb-systemd-helper update-state 'SFTPxy.service' >/dev/null || true
	fi
fi

if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
	if [ -d /run/systemd/system ]; then
		systemctl --system daemon-reload >/dev/null || true
		if [ -n "$2" ]; then
			_dh_action=restart
		else
			_dh_action=start
		fi
		deb-systemd-invoke $_dh_action 'SFTPxy.service' >/dev/null || true
	fi
fi