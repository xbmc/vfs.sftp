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

#include "xbmc/libXBMC_addon.h"
#include "xbmc/threads/mutex.h"
#include "SFTPSession.h"

#include <map>
#include <sstream>

ADDON::CHelper_libXBMC_addon *XBMC           = NULL;

extern "C" {

#include "xbmc/xbmc_vfs_dll.h"
#include "xbmc/IFileTypes.h"

//-- Create -------------------------------------------------------------------
// Called on load. Addon should fully initalize or return error status
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_Create(void* hdl, void* props)
{
  if (!XBMC)
    XBMC = new ADDON::CHelper_libXBMC_addon;

  if (!XBMC->RegisterMe(hdl))
  {
    delete XBMC, XBMC=NULL;
    return ADDON_STATUS_PERMANENT_FAILURE;
  }

  return ADDON_STATUS_OK;
}

//-- Stop ---------------------------------------------------------------------
// This dll must cease all runtime activities
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Stop()
{
}

//-- Destroy ------------------------------------------------------------------
// Do everything before unload of this add-on
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Destroy()
{
  XBMC=NULL;
}

//-- HasSettings --------------------------------------------------------------
// Returns true if this add-on use settings
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
bool ADDON_HasSettings()
{
  return false;
}

//-- GetStatus ---------------------------------------------------------------
// Returns the current Status of this visualisation
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_GetStatus()
{
  return ADDON_STATUS_OK;
}

//-- GetSettings --------------------------------------------------------------
// Return the settings for XBMC to display
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
unsigned int ADDON_GetSettings(ADDON_StructSetting ***sSet)
{
  return 0;
}

//-- FreeSettings --------------------------------------------------------------
// Free the settings struct passed from XBMC
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------

void ADDON_FreeSettings()
{
}

//-- SetSetting ---------------------------------------------------------------
// Set a specific Setting value (called from XBMC)
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_SetSetting(const char *strSetting, const void* value)
{
  return ADDON_STATUS_OK;
}

//-- Announce -----------------------------------------------------------------
// Receive announcements from XBMC
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Announce(const char *flag, const char *sender, const char *message, const void *data)
{
}

struct SFTPContext
{
  Yo::CSFTPSessionPtr session;
  sftp_file sftp_handle;
  std::string file;
};

void* Open(const char* url, const char* hostname,
           const char* filename, unsigned int port,
           const char* options, const char* username,
           const char* password)
{
  SFTPContext* result = new SFTPContext;

  result->session = Yo::CSFTPSessionManager::Get().CreateSession(hostname, port, username, password);

  if (result->session)
  {
    result->file = filename;
    result->sftp_handle = result->session->CreateFileHande(result->file);
    if (result->sftp_handle)
      return result;
  }
  else
    XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Failed to allocate session");

  delete result;
  return NULL;
}

unsigned int Read(void* context, void* lpBuf, int64_t uiBufSize)
{
  SFTPContext* ctx = (SFTPContext*)context;
  if (ctx && ctx->session && ctx->sftp_handle)
  {
    int rc = ctx->session->Read(ctx->sftp_handle, lpBuf, (size_t)uiBufSize);

    if (rc >= 0)
      return rc;
    else
      XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Failed to read %i", rc);
  }
  else
    XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Can't read without a filehandle");

  return 0;
}

bool Close(void* context)
{
  SFTPContext* ctx = (SFTPContext*)context;
  if (ctx->session && ctx->sftp_handle)
    ctx->session->CloseFileHandle(ctx->sftp_handle);
  delete ctx;
}

int64_t GetLength(void* context)
{
  SFTPContext* ctx = (SFTPContext*)context;
  struct __stat64 buffer;
  if (ctx->session->Stat(ctx->file.c_str(), &buffer) != 0)
    return 0;
  else
    return buffer.st_size;
}

//*********************************************************************************************
int64_t GetPosition(void* context)
{
  SFTPContext* ctx = (SFTPContext*)context;
  if (ctx->session && ctx->sftp_handle)
    return ctx->session->GetPosition(ctx->sftp_handle);

  XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Can't get position without a filehandle for '%s'", ctx->file.c_str());
  return 0;
}


int64_t Seek(void* context, int64_t iFilePosition, int iWhence)
{
  SFTPContext* ctx = (SFTPContext*)context;
  if (ctx && ctx->session && ctx->sftp_handle)
  {
    uint64_t position = 0;
    if (iWhence == SEEK_SET)
      position = iFilePosition;
    else if (iWhence == SEEK_CUR)
      position = GetPosition(context) + iFilePosition;
    else if (iWhence == SEEK_END)
      position = GetLength(context) + iFilePosition;

    if (ctx->session->Seek(ctx->sftp_handle, position) == 0)
      return GetPosition(context);
    else
      return -1;
  }
  else
  {
    XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Can't seek without a filehandle");
    return -1;
  }
}

bool Exists(const char* url, const char* hostname,
            const char* filename, unsigned int port,
            const char* options, const char* username,
            const char* password)
{
  Yo::CSFTPSessionPtr session = Yo::CSFTPSessionManager::Get().CreateSession(hostname,
                                                                     port,
                                                                     username,
                                                                     password);
  if (session)
    return session->FileExists(filename);
  else
  {
    XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Failed to create session to check exists for '%s'", filename);
    return false;
  }
}

int Stat(const char* url, const char* hostname,
         const char* filename, unsigned int port,
         const char* options, const char* username,
         const char* password, struct __stat64* buffer)
{
  Yo::CSFTPSessionPtr session = Yo::CSFTPSessionManager::Get().CreateSession(hostname,
                                                                     port,
                                                                     username,
                                                                     password);
  if (session)
    return session->Stat(filename, buffer);
  else
  {
    XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Failed to create session to stat for '%s'", filename);
    return -1;
  }
}

int IoControl(void* context, XFILE::EIoControl request, void* param)
{
  if(request == XFILE::IOCTRL_SEEK_POSSIBLE)
    return 1;

  return -1;
}

void ClearOutIdle()
{
  Yo::CSFTPSessionManager::Get().ClearOutIdleSessions();
}

void DisconnectAll()
{
  Yo::CSFTPSessionManager::Get().DisconnectAllSessions();
}

bool DirectoryExists(const char* url, const char* hostname,
                     const char* filename, unsigned int port,
                     const char* options, const char* username,
                     const char* password)
{
  Yo::CSFTPSessionPtr session = Yo::CSFTPSessionManager::Get().CreateSession(hostname,
                                                                     port,
                                                                     username,
                                                                     password);
  if (session)
    return session->DirectoryExists(filename);
  else
  {
    XBMC->Log(ADDON::LOG_ERROR, "SFTPFile: Failed to create session to check exists");
    return false;
  }
}

void* GetDirectory(const char* url, const char* hostname,
                   const char* filename, unsigned int port,
                   const char* options, const char* username,
                   const char* password, VFSDirEntry** items,
                   int* num_items)
{
  std::vector<VFSDirEntry>* result = new std::vector<VFSDirEntry>;
  Yo::CSFTPSessionPtr session = Yo::CSFTPSessionManager::Get().CreateSession(hostname,
                                                                             port,
                                                                             username,
                                                                             password);
  std::stringstream str;
  str << "sftp://" << username << ":" << password << "@" << hostname << ":" << port << "/";
  if (!session->GetDirectory(str.str(), filename, *result))
  {
    delete result;
    return NULL;
  }

  if (result->size())
    *items = &(*result)[0];
  *num_items = result->size();

  return result;
}

void FreeDirectory(void* items)
{
  std::vector<VFSDirEntry>& ctx = *(std::vector<VFSDirEntry>*)items;
  for (size_t i=0;i<ctx.size();++i)
  {
    free(ctx[i].label);
    for (size_t j=0;j<ctx[i].num_props;++j)
    {
      free(ctx[i].properties[j].name);
      free(ctx[i].properties[j].val);
    }
    delete ctx[i].properties;
    free(ctx[i].path);
  }
  delete &ctx;
}

void* OpenForWrite(const char* url, const char* hostname,
                   const char* filename2, unsigned int port,
                   const char* options, const char* username,
                   const char* password, bool bOverWrite)
{
  return NULL;
}

bool Rename(const char* url, const char* hostname,
            const char* filename, unsigned int port,
            const char* options, const char* username,
            const char* password,
            const char* url2, const char* hostname2,
            const char* filename2, unsigned int port2,
            const char* options2, const char* username2,
            const char* password2)
{
  return false;
}

bool Delete(const char* url, const char* hostname,
            const char* filename2, unsigned int port,
            const char* options, const char* username,
            const char* password)
{
  return false;
}

int Write(void* context, const void* lpBuf, int64_t uiBufSize)
{
  return -1;
}

int Truncate(void* context, int64_t size)
{
  return -1;
}

bool RemoveDirectory(const char* url, const char* hostname,
                     const char* filename, unsigned int port,
                     const char* options, const char* username,
                     const char* password)
{
  return false;
}

bool CreateDirectory(const char* url, const char* hostname,
                     const char* filename, unsigned int port,
                     const char* options, const char* username,
                     const char* password)
{
  return false;
}

void* ContainsFiles(const char* url, const char* hostname,
                    const char* filename2, unsigned int port,
                    const char* options, const char* username,
                    const char* password,
                    VFSDirEntry** items, int* num_items)
{
  return NULL;
}

int GetStartTime(void* ctx)
{
  return 0;
}

int GetTotalTime(void* ctx)
{
  return 0;
}

bool NextChannel(void* context, bool preview)
{
  return false;
}

bool PrevChannel(void* context, bool preview)
{
  return false;
}

bool SelectChannel(void* context, unsigned int uiChannel)
{
  return false;
}

bool UpdateItem(void* context)
{
  return false;
}

}
