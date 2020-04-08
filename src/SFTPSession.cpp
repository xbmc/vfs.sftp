/*
 *  Copyright (C) 2005-2020 Team Kodi
 *  https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include "SFTPSession.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sstream>
#include <kodi/General.h>

#define SFTP_TIMEOUT 10
#if !defined(S_ISREG)
#define S_ISREG(m) ((m & _S_IFREG) != 0)
#endif

static std::string CorrectPath(const std::string& path)
{
  if (path == "~")
    return "./";
  else if (path.substr(0, 2) == "~/")
    return "./" + path.substr(2);
  else
    return "/" + path;
}

static const char * SFTPErrorText(int sftp_error)
{
  switch(sftp_error)
  {
    case SSH_FX_OK:
      return "No error";
    case SSH_FX_EOF:
      return "End-of-file encountered";
    case SSH_FX_NO_SUCH_FILE:
      return "File doesn't exist";
    case SSH_FX_PERMISSION_DENIED:
      return "Permission denied";
    case SSH_FX_BAD_MESSAGE:
      return "Garbage received from server";
    case SSH_FX_NO_CONNECTION:
      return "No connection has been set up";
    case SSH_FX_CONNECTION_LOST:
      return "There was a connection, but we lost it";
    case SSH_FX_OP_UNSUPPORTED:
      return "Operation not supported by the server";
    case SSH_FX_INVALID_HANDLE:
      return "Invalid file handle";
    case SSH_FX_NO_SUCH_PATH:
      return "No such file or directory path exists";
    case SSH_FX_FILE_ALREADY_EXISTS:
      return "An attempt to create an already existing file or directory has been made";
    case SSH_FX_WRITE_PROTECT:
      return "We are trying to write on a write-protected filesystem";
    case SSH_FX_NO_MEDIA:
      return "No media in remote drive";
    case -1:
      return "Not a valid error code, probably called on an invalid session";
    default:
      kodi::Log(ADDON_LOG_ERROR, "SFTPErrorText: Unknown error code: %d", sftp_error);
  }
  return "Unknown error code";
}

CSFTPSession::CSFTPSession(const VFSURL& url)
{
  kodi::Log(ADDON_LOG_INFO, "SFTPSession: Creating new session on host '%s:%d' with user '%s'", url.hostname, url.port, url.username);
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  if (!Connect(url))
    Disconnect();

  m_LastActive = std::chrono::high_resolution_clock::now();
}

CSFTPSession::~CSFTPSession()
{
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  Disconnect();
}

sftp_file CSFTPSession::CreateFileHande(const std::string& file)
{
  if (m_connected)
  {
    std::unique_lock<std::recursive_mutex> lock(m_lock);
    m_LastActive = std::chrono::high_resolution_clock::now();
    sftp_file handle = sftp_open(m_sftp_session, CorrectPath(file).c_str(), O_RDONLY, 0);
    if (handle)
    {
      sftp_file_set_blocking(handle);
      return handle;
    }
    else
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Was connected but couldn't create filehandle for '%s'", file.c_str());
  }
  else
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Not connected and can't create file handle for '%s'", file.c_str());

  return nullptr;
}

void CSFTPSession::CloseFileHandle(sftp_file handle)
{
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  sftp_close(handle);
}

bool CSFTPSession::GetDirectory(const std::string& base, const std::string& folder,
                                std::vector<kodi::vfs::CDirEntry>& items)
{
  int sftp_error = SSH_FX_OK;
  if (m_connected)
  {
    sftp_dir dir = nullptr;

    std::unique_lock<std::recursive_mutex> lock(m_lock);
    m_LastActive = std::chrono::high_resolution_clock::now();
    dir = sftp_opendir(m_sftp_session, CorrectPath(folder).c_str());

    //Doing as little work as possible within the critical section
    if (!dir)
      sftp_error = sftp_get_error(m_sftp_session);

    lock.unlock();

    if (!dir)
    {
      kodi::Log(ADDON_LOG_ERROR, "%s: %s for '%s'", __FUNCTION__, SFTPErrorText(sftp_error), folder.c_str());
    }
    else
    {
      bool read = true;
      while (read)
      {
        sftp_attributes attributes = nullptr;

        lock.lock();
        read = sftp_dir_eof(dir) == 0;
        attributes = sftp_readdir(m_sftp_session, dir);
        lock.unlock();

        if (attributes && (attributes->name == nullptr || strcmp(attributes->name, "..") == 0 || strcmp(attributes->name, ".") == 0))
        {
          lock.lock();
          sftp_attributes_free(attributes);
          lock.unlock();
          continue;
        }

        if (attributes)
        {
          std::string itemName = attributes->name;
          std::string localPath = folder;
          localPath.append(itemName);

          if (attributes->type == SSH_FILEXFER_TYPE_SYMLINK)
          {
            lock.lock();
            sftp_attributes_free(attributes);
            attributes = sftp_stat(m_sftp_session, CorrectPath(localPath).c_str());
            lock.unlock();
            if (attributes == nullptr)
              continue;
          }

          kodi::vfs::CDirEntry entry;
          entry.SetLabel(itemName);

          if (itemName[0] == '.')
            entry.AddProperty("file:hidden", "true");

          entry.SetDateTime(attributes->mtime);

          if (attributes->type & SSH_FILEXFER_TYPE_DIRECTORY)
          {
            localPath.append("/");
            entry.SetFolder(true);
            entry.SetSize(0);
          }
          else
            entry.SetSize(attributes->size);

          entry.SetPath(base+localPath);
          items.push_back(entry);

          lock.lock();
          sftp_attributes_free(attributes);
          lock.unlock();
        }
        else
          read = false;
      }

      lock.lock();
      sftp_closedir(dir);
      lock.unlock();

      return true;
    }
  }
  else
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Not connected, can't list directory '%s'", folder.c_str());

  return false;
}

bool CSFTPSession::DirectoryExists(const char *path)
{
  bool exists = false;
  uint32_t permissions = 0;
  exists = GetItemPermissions(path, permissions);
  return exists && S_ISDIR(permissions);
}

bool CSFTPSession::FileExists(const char *path)
{
  bool exists = false;
  uint32_t permissions = 0;
  exists = GetItemPermissions(path, permissions);
  return exists && S_ISREG(permissions);
}

int CSFTPSession::Stat(const char *path, struct __stat64* buffer)
{
  if(m_connected)
  {
    std::unique_lock<std::recursive_mutex> lock(m_lock);
    m_LastActive = std::chrono::high_resolution_clock::now();
    sftp_attributes attributes = sftp_stat(m_sftp_session, CorrectPath(path).c_str());

    if (attributes)
    {
      memset(buffer, 0, sizeof(struct __stat64));
      buffer->st_size = attributes->size;
      buffer->st_mtime = attributes->mtime;
      buffer->st_atime = attributes->atime;

      if S_ISDIR(attributes->permissions)
        buffer->st_mode = S_IFDIR;
      else if S_ISREG(attributes->permissions)
        buffer->st_mode = S_IFREG;

      sftp_attributes_free(attributes);
      return 0;
    }
    else
    {
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession::Stat - Failed to get attributes for '%s'", path);
      return -1;
    }
  }
  else
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession::Stat - Failed because not connected for '%s'", path);
    return -1;
  }
}

int CSFTPSession::Seek(sftp_file handle, uint64_t position)
{
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  m_LastActive = std::chrono::high_resolution_clock::now();
  int result = sftp_seek64(handle, position);
  return result;
}

int CSFTPSession::Read(sftp_file handle, void *buffer, size_t length)
{
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  m_LastActive = std::chrono::high_resolution_clock::now();
  int result=sftp_read(handle, buffer, length);
  return result;
}

int64_t CSFTPSession::GetPosition(sftp_file handle)
{
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  m_LastActive = std::chrono::high_resolution_clock::now();
  int64_t result = sftp_tell64(handle);
  return result;
}

bool CSFTPSession::IsIdle()
{
  std::chrono::high_resolution_clock::time_point now = std::chrono::high_resolution_clock::now();
  return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(now - m_LastActive).count()) > 90000;
}

bool CSFTPSession::VerifyKnownHost(ssh_session session)
{
#if !(LIBSSH_VERSION_MAJOR == 0 && LIBSSH_VERSION_MINOR < 8)
  // Code used on libssh 0.8.0 and above
  // See https://api.libssh.org/stable/deprecated.html
  switch (ssh_session_is_known_server(session))
  {
    case SSH_KNOWN_HOSTS_OK:
      return true;
    case SSH_KNOWN_HOSTS_CHANGED:
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Server that was known has changed");
      return false;
    case SSH_KNOWN_HOSTS_OTHER:
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: The host key for this server was not found but an other type of key exists. An attacker might change the default server key to confuse your client into thinking the key does not exist");
      return false;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
      kodi::Log(ADDON_LOG_INFO, "SFTPSession: Server file was not found, creating a new one");
    case SSH_KNOWN_HOSTS_UNKNOWN:
      kodi::Log(ADDON_LOG_INFO, "SFTPSession: Server unkown, we trust it for now");
      if (ssh_session_update_known_hosts(session) != SSH_OK)
      {
        kodi::Log(ADDON_LOG_ERROR, "CSFTPSession: Failed to save host '%s'", strerror(errno));
        return false;
      }

      return true;
    case SSH_KNOWN_HOSTS_ERROR:
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to verify host '%s'", ssh_get_error(session));
      return false;
  }
#else
  switch (ssh_is_server_known(session))
  {
    case SSH_SERVER_KNOWN_OK:
      return true;
    case SSH_SERVER_KNOWN_CHANGED:
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Server that was known has changed");
      return false;
    case SSH_SERVER_FOUND_OTHER:
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: The host key for this server was not found but an other type of key exists. An attacker might change the default server key to confuse your client into thinking the key does not exist");
      return false;
    case SSH_SERVER_FILE_NOT_FOUND:
      kodi::Log(ADDON_LOG_INFO, "SFTPSession: Server file was not found, creating a new one");
    case SSH_SERVER_NOT_KNOWN:
      kodi::Log(ADDON_LOG_INFO, "SFTPSession: Server unkown, we trust it for now");
      if (ssh_write_knownhost(session) < 0)
      {
        kodi::Log(ADDON_LOG_ERROR, "CSFTPSession: Failed to save host '%s'", strerror(errno));
        return false;
      }

      return true;
    case SSH_SERVER_ERROR:
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to verify host '%s'", ssh_get_error(session));
      return false;
  }
#endif

  return false;
}

bool CSFTPSession::Connect(const VFSURL& url)
{
  int timeout     = SFTP_TIMEOUT;
  m_connected     = false;
  m_session       = nullptr;
  m_sftp_session  = nullptr;

  m_session=ssh_new();
  if (m_session == nullptr)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to initialize session for host '%s'", url.hostname);
    return false;
  }

  if (ssh_options_set(m_session, SSH_OPTIONS_USER, url.username) < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to set username '%s' for session", url.username);
    return false;
  }

  if (ssh_options_set(m_session, SSH_OPTIONS_HOST, url.hostname) < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to set host '%s' for session", url.hostname);
    return false;
  }

  if (ssh_options_set(m_session, SSH_OPTIONS_PORT, &url.port) < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to set port '%d' for session", url.port);
    return false;
  }

#if defined(TARGET_DARWIN_IOS) || defined(TARGET_WINDOWS_STORE)
  std::string sshFolder = kodi::vfs::TranslateSpecialProtocol("special://home/.ssh");
  if (ssh_options_set(m_session, SSH_OPTIONS_SSH_DIR, sshFolder.c_str()) < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to set .ssh folder to '%s' for session", sshFolder.c_str());
    return false;
  }
#endif

  ssh_options_set(m_session, SSH_OPTIONS_LOG_VERBOSITY, 0);
  ssh_options_set(m_session, SSH_OPTIONS_TIMEOUT, &timeout);

  if(ssh_connect(m_session))
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to connect '%s'", ssh_get_error(m_session));
    return false;
  }

  if (!VerifyKnownHost(m_session))
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Host is not known '%s'", ssh_get_error(m_session));
    return false;
  }

  int noAuth = SSH_AUTH_DENIED;
  if ((noAuth = ssh_userauth_none(m_session, nullptr)) == SSH_AUTH_ERROR)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to authenticate via guest '%s'", ssh_get_error(m_session));
    return false;
  }

  int method = ssh_userauth_list(m_session, nullptr);

  // Try to authenticate with public key first
  int publicKeyAuth = SSH_AUTH_DENIED;
  if (method & SSH_AUTH_METHOD_PUBLICKEY && (publicKeyAuth = ssh_userauth_publickey_auto(m_session, nullptr, nullptr)) == SSH_AUTH_ERROR)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to authenticate via publickey '%s'", ssh_get_error(m_session));
    return false;
  }

  // Try to authenticate with password
  int passwordAuth = SSH_AUTH_DENIED;
  if (method & SSH_AUTH_METHOD_PASSWORD)
  {
    if (publicKeyAuth != SSH_AUTH_SUCCESS &&
        (passwordAuth = ssh_userauth_password(m_session, url.username, url.password)) == SSH_AUTH_ERROR)
      {
        kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to authenticate via password '%s'", ssh_get_error(m_session));
        return false;
      }
  }
  else if (strlen(url.password) > 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Password present, but server does not support password authentication");
  }

  if (noAuth == SSH_AUTH_SUCCESS || publicKeyAuth == SSH_AUTH_SUCCESS || passwordAuth == SSH_AUTH_SUCCESS)
  {
    m_sftp_session = sftp_new(m_session);

    if (m_sftp_session == nullptr)
    {
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to initialize channel '%s'", ssh_get_error(m_session));
      return false;
    }

    if (sftp_init(m_sftp_session))
    {
      kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to initialize sftp '%s'", ssh_get_error(m_session));
      return false;
    }

    m_connected = true;
  }
  else
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: No authentication method successful");
  }

  return m_connected;
}

void CSFTPSession::Disconnect()
{
  if (m_sftp_session)
    sftp_free(m_sftp_session);

  if (m_session)
  {
    ssh_disconnect(m_session);
    ssh_free(m_session);
  }

  m_sftp_session = nullptr;
  m_session = nullptr;
}

/*!
 \brief Gets POSIX compatible permissions information about the specified file or directory.
 \param path Remote SSH path to the file or directory.
 \param permissions POSIX compatible permissions information for the file or directory (if it exists). i.e. can use macros S_ISDIR() etc.
 \return Returns \e true, if it was possible to get permissions for the file or directory, \e false otherwise.
 */
bool CSFTPSession::GetItemPermissions(const char *path, uint32_t &permissions)
{
  bool gotPermissions = false;
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  if(m_connected)
  {
    sftp_attributes attributes = sftp_stat(m_sftp_session, CorrectPath(path).c_str());
    if (attributes)
    {
      if (attributes->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
      {
        permissions = attributes->permissions;
        gotPermissions = true;
      }

      sftp_attributes_free(attributes);
    }
  }
  return gotPermissions;
}

CSFTPSessionManager& CSFTPSessionManager::Get()
{
  static CSFTPSessionManager instance;

  return instance;
}

CSFTPSessionPtr CSFTPSessionManager::CreateSession(const VFSURL& url)
{
  VFSURL url2 = url;
  // Check if url contains port, else fallback to 22 (default)
  if (url2.port == 0)
    url2.port = 22;

  // Convert port number to string
  std::stringstream itoa;
  itoa << url2.port;
  std::string portstr = itoa.str();

  std::unique_lock<std::recursive_mutex> lock(m_lock);
  std::string key = std::string(url2.username) + ":" +
                    url2.password + "@" + url2.hostname + ":" + portstr;
  CSFTPSessionPtr ptr = sessions[key];
  if (ptr == nullptr)
  {
    ptr = CSFTPSessionPtr(new CSFTPSession(url2));
    sessions[key] = ptr;
  }

  return ptr;
}

void CSFTPSessionManager::ClearOutIdleSessions()
{
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  for(std::map<std::string, CSFTPSessionPtr>::iterator iter = sessions.begin(); iter != sessions.end();)
  {
    if (iter->second->IsIdle())
      sessions.erase(iter++);
    else
      iter++;
  }
}

void CSFTPSessionManager::DisconnectAllSessions()
{
  std::unique_lock<std::recursive_mutex> lock(m_lock);
  sessions.clear();
}
