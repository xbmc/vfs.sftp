/*
 *      Copyright (C) 2005-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include "SFTPSession.h"
#include "util/timeutils.h"
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
  P8PLATFORM::CLockObject lock(m_lock);
  if (!Connect(url))
    Disconnect();

  m_LastActive = P8PLATFORM::GetTimeMs();
}

CSFTPSession::~CSFTPSession()
{
  P8PLATFORM::CLockObject lock(m_lock);
  Disconnect();
}

sftp_file CSFTPSession::CreateFileHande(const std::string& file)
{
  if (m_connected)
  {
    P8PLATFORM::CLockObject lock(m_lock);
    m_LastActive = P8PLATFORM::GetTimeMs();
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

  return NULL;
}

void CSFTPSession::CloseFileHandle(sftp_file handle)
{
  P8PLATFORM::CLockObject lock(m_lock);
  sftp_close(handle);
}

bool CSFTPSession::GetDirectory(const std::string& base, const std::string& folder,
                                std::vector<kodi::vfs::CDirEntry>& items)
{
  int sftp_error = SSH_FX_OK;
  if (m_connected)
  {
    sftp_dir dir = NULL;

    P8PLATFORM::CLockObject lock(m_lock);
    m_LastActive = P8PLATFORM::GetTimeMs();
    dir = sftp_opendir(m_sftp_session, CorrectPath(folder).c_str());

    //Doing as little work as possible within the critical section
    if (!dir)
      sftp_error = sftp_get_error(m_sftp_session);

    lock.Unlock();

    if (!dir)
    {
      kodi::Log(ADDON_LOG_ERROR, "%s: %s for '%s'", __FUNCTION__, SFTPErrorText(sftp_error), folder.c_str());
    }
    else
    {
      bool read = true;
      while (read)
      {
        sftp_attributes attributes = NULL;

        lock.Lock();
        read = sftp_dir_eof(dir) == 0;
        attributes = sftp_readdir(m_sftp_session, dir);
        lock.Unlock();

        if (attributes && (attributes->name == NULL || strcmp(attributes->name, "..") == 0 || strcmp(attributes->name, ".") == 0))
        {
          lock.Lock();
          sftp_attributes_free(attributes);
          lock.Unlock();
          continue;
        }

        if (attributes)
        {
          std::string itemName = attributes->name;
          std::string localPath = folder;
          localPath.append(itemName);

          if (attributes->type == SSH_FILEXFER_TYPE_SYMLINK)
          {
            lock.Lock();
            sftp_attributes_free(attributes);
            attributes = sftp_stat(m_sftp_session, CorrectPath(localPath).c_str());
            lock.Unlock();
            if (attributes == NULL)
              continue;
          }

          kodi::vfs::CDirEntry entry;
          entry.SetLabel(itemName);

          if (itemName[0] == '.')
            entry.AddProperty("file:hidden", "true");

          entry.SetDateTime(attributes->mtime64);

          if (attributes->type & SSH_FILEXFER_TYPE_DIRECTORY)
          {
            localPath.append("/");
            entry.SetFolder(true);
          }
          else
            entry.SetSize(attributes->size);

          entry.SetPath(base+localPath);
          items.push_back(entry);

          lock.Lock();
          sftp_attributes_free(attributes);
          lock.Unlock();
        }
        else
          read = false;
      }

      lock.Lock();
      sftp_closedir(dir);
      lock.Unlock();

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
    P8PLATFORM::CLockObject lock(m_lock);
    m_LastActive = P8PLATFORM::GetTimeMs();
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
  P8PLATFORM::CLockObject lock(m_lock);
  m_LastActive = P8PLATFORM::GetTimeMs();
  int result = sftp_seek64(handle, position);
  return result;
}

int CSFTPSession::Read(sftp_file handle, void *buffer, size_t length)
{
  P8PLATFORM::CLockObject lock(m_lock);
  m_LastActive = P8PLATFORM::GetTimeMs();
  int result=sftp_read(handle, buffer, length);
  return result;
}

int64_t CSFTPSession::GetPosition(sftp_file handle)
{
  P8PLATFORM::CLockObject lock(m_lock);
  m_LastActive = P8PLATFORM::GetTimeMs();
  int64_t result = sftp_tell64(handle);
  return result;
}

bool CSFTPSession::IsIdle()
{
  return (P8PLATFORM::GetTimeMs() - m_LastActive) > 90000;
}

bool CSFTPSession::VerifyKnownHost(ssh_session session)
{
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

  return false;
}

bool CSFTPSession::Connect(const VFSURL& url)
{
  int timeout     = SFTP_TIMEOUT;
  m_connected     = false;
  m_session       = NULL;
  m_sftp_session  = NULL;

  m_session=ssh_new();
  if (m_session == NULL)
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
  if ((noAuth = ssh_userauth_none(m_session, NULL)) == SSH_AUTH_ERROR)
  {
    kodi::Log(ADDON_LOG_ERROR, "SFTPSession: Failed to authenticate via guest '%s'", ssh_get_error(m_session));
    return false;
  }

  int method = ssh_userauth_list(m_session, NULL);

  // Try to authenticate with public key first
  int publicKeyAuth = SSH_AUTH_DENIED;
  if (method & SSH_AUTH_METHOD_PUBLICKEY && (publicKeyAuth = ssh_userauth_publickey_auto(m_session, NULL, NULL)) == SSH_AUTH_ERROR)
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

    if (m_sftp_session == NULL)
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

  m_sftp_session = NULL;
  m_session = NULL;
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
  P8PLATFORM::CLockObject lock(m_lock);
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
  // Convert port number to string
  std::stringstream itoa;
  itoa << (url.port ? url.port : 22);
  std::string portstr = itoa.str();

  P8PLATFORM::CLockObject lock(m_lock);
  std::string key = std::string(url.username) + ":" +
                    url.password + "@" + url.hostname + ":" + portstr;
  CSFTPSessionPtr ptr = sessions[key];
  if (ptr == NULL)
  {
    ptr = CSFTPSessionPtr(new CSFTPSession(url));
    sessions[key] = ptr;
  }

  return ptr;
}

void CSFTPSessionManager::ClearOutIdleSessions()
{
  P8PLATFORM::CLockObject lock(m_lock);
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
  P8PLATFORM::CLockObject lock(m_lock);
  sessions.clear();
}
