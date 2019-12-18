/*
 *      Copyright (C) 2005-2019 Team Kodi
 *      https://kodi.tv
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
 *  along with Kodi; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include <chrono>
#include <kodi/addon-instance/VFS.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class CSFTPSession
{
public:
  CSFTPSession(const VFSURL& url);
  virtual ~CSFTPSession();

  sftp_file CreateFileHande(const std::string& file);
  void CloseFileHandle(sftp_file handle);
  bool GetDirectory(const std::string& base, const std::string& folder,
                    std::vector<kodi::vfs::CDirEntry>& items);
  bool DirectoryExists(const char *path);
  bool FileExists(const char *path);
  int Stat(const char *path, struct __stat64* buffer);
  int Seek(sftp_file handle, uint64_t position);
  int Read(sftp_file handle, void *buffer, size_t length);
  int64_t GetPosition(sftp_file handle);
  bool IsIdle();

private:
  bool VerifyKnownHost(ssh_session session);
  bool Connect(const VFSURL& url);
  void Disconnect();
  bool GetItemPermissions(const char *path, uint32_t &permissions);
  std::recursive_mutex m_lock;

  bool m_connected;
  ssh_session  m_session;
  sftp_session m_sftp_session;
  std::chrono::high_resolution_clock::time_point m_LastActive;
};

typedef std::shared_ptr<CSFTPSession> CSFTPSessionPtr;

class CSFTPSessionManager
{
public:
  static CSFTPSessionManager& Get();
  CSFTPSessionPtr CreateSession(const VFSURL& url);
  void ClearOutIdleSessions();
  void DisconnectAllSessions();

private:
  CSFTPSessionManager() {}
  CSFTPSessionManager& operator=(const CSFTPSessionManager&);
  std::recursive_mutex m_lock;
  std::map<std::string, CSFTPSessionPtr> sessions;
};
