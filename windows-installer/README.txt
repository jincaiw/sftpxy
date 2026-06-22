SFTPxy allows you to securely share files over SFTP and optionally over HTTP/S, FTP/S and WebDAV.
Several storage backends are supported, including local filesystem, encrypted local filesystem,
S3-compatible object storage, Google Cloud Storage, Azure Blob Storage, and other SFTP servers.

If this is your first installation, open the web administration panel:

http://localhost:30080/web/admin/login

The WebClient is available at:

http://localhost:30081/web/client/login

The SFTP service is available, by default, on port 30082.

If the SFTPxy service does not start, make sure that TCP ports 30080, 30081, 30082, and
30085-30088 are not used by other services or change the SFTPxy configuration.

Default data location:

C:\ProgramData\SFTPxy

Configuration file location:

C:\ProgramData\SFTPxy\SFTPxy.json

Directory to create environment variable files to set configuration options:

C:\ProgramData\SFTPxy\env.d

It is recommended that you set custom configurations as environment variables by creating files in
the env.d directory.
This eliminates the need to merge your changes with the default configuration file after each update.
You can simply replace the configuration file with the default one after updating SFTPxy.

Source code and documentation:

https://github.com/jincaiw/sftpxy

If you find a bug please open an issue:

https://github.com/jincaiw/sftpxy/issues

If you want to suggest a new feature or have a question, please start a new discussion:

https://github.com/jincaiw/sftpxy/discussions
