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

#include <p8-platform/threads/mutex.h>
#include <kodi/addon-instance/VFS.h>
#include <kodi/General.h>
#include "SFTPSession.h"

#include <map>
#include <sstream>

class ATTRIBUTE_HIDDEN CSFTPFile : public kodi::addon::CInstanceVFS
{
  struct SFTPContext
  {
    CSFTPSessionPtr session;
    sftp_file sftp_handle;
    std::string file;
  };

public:
  CSFTPFile(KODI_HANDLE instance) : CInstanceVFS(instance) { }

  virtual void* Open(const VFSURL& url) override
  {
    SFTPContext* result = new SFTPContext;

    result->session = CSFTPSessionManager::Get().CreateSession(url);

    if (result->session)
    {
      result->file = url.filename;
      result->sftp_handle = result->session->CreateFileHande(result->file);
      if (result->sftp_handle)
        return result;
    }
    else
      kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Failed to allocate session");

    delete result;
    return nullptr;
  }

  virtual ssize_t Read(void* context, void* buffer, size_t uiBufSize) override
  {
    SFTPContext* ctx = (SFTPContext*)context;
    if (ctx && ctx->session && ctx->sftp_handle)
    {
      int rc = ctx->session->Read(ctx->sftp_handle, buffer, uiBufSize);

      if (rc >= 0)
        return rc;
      else
        kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Failed to read %i", rc);
    }
    else
      kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Can't read without a handle");

    return -1;
  }

  virtual int64_t Seek(void* context, int64_t iFilePosition, int whence) override
  {
    SFTPContext* ctx = (SFTPContext*)context;
    if (ctx && ctx->session && ctx->sftp_handle)
    {
      uint64_t position = 0;
      if (whence == SEEK_SET)
        position = iFilePosition;
      else if (whence == SEEK_CUR)
        position = GetPosition(context) + iFilePosition;
      else if (whence == SEEK_END)
        position = GetLength(context) + iFilePosition;

      if (ctx->session->Seek(ctx->sftp_handle, position) == 0)
        return GetPosition(context);
      else
        return -1;
    }
    else
    {
      kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Can't seek without a handle");
      return -1;
    }
  }

  virtual int64_t GetLength(void* context) override
  {
    SFTPContext* ctx = (SFTPContext*)context;
    struct __stat64 buffer;
    if (ctx->session->Stat(ctx->file.c_str(), &buffer) != 0)
      return 0;
    else
      return buffer.st_size;
  }

  virtual int64_t GetPosition(void* context) override
  {
    SFTPContext* ctx = (SFTPContext*)context;
    if (ctx->session && ctx->sftp_handle)
      return ctx->session->GetPosition(ctx->sftp_handle);

    kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Can't get position without a handle for '%s'", ctx->file.c_str());
    return 0;
  }

  virtual int IoControl(void* context, XFILE::EIoControl request, void* param) override
  {
    if(request == XFILE::IOCTRL_SEEK_POSSIBLE)
      return 1;

    return -1;
  }

  virtual int Stat(const VFSURL& url, struct __stat64* buffer) override
  {
    CSFTPSessionPtr session = CSFTPSessionManager::Get().CreateSession(url);
    if (session)
      return session->Stat(url.filename, buffer);
    else
    {
      kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Failed to create session to stat for '%s'", url.filename);
      return -1;
    }
  }

  virtual bool Close(void* context) override
  {
    SFTPContext* ctx = (SFTPContext*)context;
    if (ctx->session && ctx->sftp_handle)
      ctx->session->CloseFileHandle(ctx->sftp_handle);
    delete ctx;

    return true;
  }

  virtual bool Exists(const VFSURL& url) override
  {
    CSFTPSessionPtr session = CSFTPSessionManager::Get().CreateSession(url);
    if (session)
      return session->FileExists(url.filename);
    else
    {
      kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Failed to create session to check exists for '%s'", url.filename);
      return false;
    }
  }

  virtual void ClearOutIdle() override
  {
    CSFTPSessionManager::Get().ClearOutIdleSessions();
  }

  virtual void DisconnectAll() override
  {
    CSFTPSessionManager::Get().DisconnectAllSessions();
  }

  virtual bool DirectoryExists(const VFSURL& url) override
  {
    CSFTPSessionPtr session = CSFTPSessionManager::Get().CreateSession(url);
    if (session)
      return session->DirectoryExists(url.filename);
    else
    {
      kodi::Log(ADDON_LOG_ERROR, "SFTPFile: Failed to create session to check exists");
      return false;
    }
  }

  virtual bool GetDirectory(const VFSURL& url,
                            std::vector<kodi::vfs::CDirEntry>& items,
                            CVFSCallbacks callbacks) override
  {
    CSFTPSessionPtr session = CSFTPSessionManager::Get().CreateSession(url);
    std::stringstream str;
    str << url.protocol << "://" << url.username << ":" << url.password
        << "@" << url.hostname << ":" << (url.port ? url.port : 22) << "/";

    return session->GetDirectory(str.str(), url.filename, items);
  }
};

class ATTRIBUTE_HIDDEN CMyAddon : public kodi::addon::CAddonBase
{
public:
  CMyAddon()
  {
    ssh_init();
  }

  ~CMyAddon()
  {
    ssh_finalize();
  }

  virtual ADDON_STATUS CreateInstance(int instanceType, std::string instanceID, KODI_HANDLE instance, KODI_HANDLE& addonInstance) override
  {
    addonInstance = new CSFTPFile(instance);
    return ADDON_STATUS_OK;
  }
};

ADDONCREATOR(CMyAddon);
