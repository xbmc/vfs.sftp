/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#pragma once

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
  CSFTPSession(const kodi::addon::VFSUrl& url);
  virtual ~CSFTPSession();

  sftp_file CreateFileHande(const std::string& file);
  void CloseFileHandle(sftp_file handle);
  bool GetDirectory(const std::string& base,
                    const std::string& folder,
                    std::vector<kodi::vfs::CDirEntry>& items);
  bool DirectoryExists(const std::string& path);
  bool FileExists(const std::string& path);
  int Stat(const std::string& path, kodi::vfs::FileStatus& buffer);
  int Seek(sftp_file handle, uint64_t position);
  int Read(sftp_file handle, void* buffer, size_t length);
  int64_t GetPosition(sftp_file handle);
  bool IsIdle();
  bool DeleteFile(const std::string& path);
  bool DeleteDirectory(const std::string& path);
  bool CreateDirectory(const std::string& path);
  bool RenameFile(const std::string& path_from, const std::string& path_to);

private:
  bool VerifyKnownHost(ssh_session session);
  bool Connect(const kodi::addon::VFSUrl& url);
  void Disconnect();
  bool GetItemPermissions(const std::string& path, uint32_t& permissions);
  std::recursive_mutex m_lock;

  bool m_connected;
  ssh_session m_session;
  sftp_session m_sftp_session;
  std::chrono::high_resolution_clock::time_point m_LastActive;
};

typedef std::shared_ptr<CSFTPSession> CSFTPSessionPtr;

class CSFTPSessionManager
{
public:
  static CSFTPSessionManager& Get();
  CSFTPSessionPtr CreateSession(const kodi::addon::VFSUrl& url);
  void ClearOutIdleSessions();
  void DisconnectAllSessions();

private:
  CSFTPSessionManager() {}
  CSFTPSessionManager& operator=(const CSFTPSessionManager&);
  std::recursive_mutex m_lock;
  std::map<std::string, CSFTPSessionPtr> sessions;
};
