/* Small Windows launcher. Local HMAC proves installation ownership, not publisher
 * authenticity. Every declared program file is hashed before CreateProcessW.
 * No Python, scanner engine, target project or network access is needed here. */
#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int nativepath(const wchar_t *path,wchar_t output[32768]) {
    if(wcslen(path)>32760) return 0;
    if(!wcsncmp(path,L"\\\\?\\",4)) {wcscpy(output,path);return 1;}
    return swprintf(output,32768,L"\\\\?\\%ls",path)>=0;
}

static int safe(const wchar_t *path) {
    wchar_t copy[32768],native[32768]; size_t n=wcslen(path);
    if(n>=32768 || n<3 || path[1]!=L':') return 0;
    wcscpy(copy,path);
    for(size_t i=3;i<=n;i++) if(copy[i]==L'\\' || copy[i]==0) {
        wchar_t saved=copy[i]; copy[i]=0;
        if(!nativepath(copy,native)) return 0;
        DWORD a=GetFileAttributesW(native); copy[i]=saved;
        if(a==INVALID_FILE_ATTRIBUTES || (a&FILE_ATTRIBUTE_REPARSE_POINT)) return 0;
    }
    return 1;
}
static char *readfile(const wchar_t *p, DWORD limit, DWORD *length) {
    if(!safe(p)) return NULL;
    wchar_t native[32768]; if(!nativepath(p,native)) return NULL;
    HANDLE h=CreateFileW(native,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER size; char *s=NULL; DWORD got=0;
    if(GetFileSizeEx(h,&size) && size.QuadPart>0 && size.QuadPart<=limit) {
        s=calloc((size_t)size.QuadPart+1,1);
        if(!s || !ReadFile(h,s,(DWORD)size.QuadPart,&got,NULL) || got!=size.QuadPart) {free(s);s=NULL;}
    }
    CloseHandle(h); if(s) *length=got; return s;
}
static int digest(const unsigned char *data, DWORD length, const unsigned char *key,
                  DWORD keylength, char out[65]) {
    BCRYPT_ALG_HANDLE alg=NULL; BCRYPT_HASH_HANDLE hash=NULL; unsigned char bytes[32];
    int ok=0;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,key?BCRYPT_ALG_HANDLE_HMAC_FLAG:0)<0) goto done;
    if(BCryptCreateHash(alg,&hash,NULL,0,(PUCHAR)key,keylength,0)<0) goto done;
    if(BCryptHashData(hash,(PUCHAR)data,length,0)<0 || BCryptFinishHash(hash,bytes,32,0)<0) goto done;
    for(int i=0;i<32;i++) sprintf(out+2*i,"%02x",bytes[i]);
    ok=1;
done: if(hash) BCryptDestroyHash(hash); if(alg) BCryptCloseAlgorithmProvider(alg,0); return ok;
}
static int filehash(const wchar_t *p,char out[65]) {
    if(!safe(p)) return 0;
    wchar_t native[32768]; if(!nativepath(p,native)) return 0;
    HANDLE file=CreateFileW(native,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(file==INVALID_HANDLE_VALUE) return 0;
    BCRYPT_ALG_HANDLE alg=NULL; BCRYPT_HASH_HANDLE hash=NULL; BYTE block[65536],bytes[32]; DWORD got; int ok=0;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0)<0 ||
       BCryptCreateHash(alg,&hash,NULL,0,NULL,0,0)<0) goto done;
    for(;;) {
        if(!ReadFile(file,block,sizeof(block),&got,NULL)) goto done;
        if(!got) break;
        if(BCryptHashData(hash,block,got,0)<0) goto done;
    }
    if(BCryptFinishHash(hash,bytes,32,0)<0) goto done;
    for(int i=0;i<32;i++) sprintf(out+2*i,"%02x",bytes[i]);
    ok=1;
done: if(hash) BCryptDestroyHash(hash); if(alg) BCryptCloseAlgorithmProvider(alg,0); CloseHandle(file); return ok;
}
static int hex64(const char *s) {
    if(strlen(s)!=64) return 0;
    for(int i=0;i<64;i++) if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return 0;
    return 1;
}
static const char *space(const char *s) {while(*s==' '||*s=='\n'||*s=='\r'||*s=='\t') s++; return s;}
static BOOL WINAPI control(DWORD signal) {return signal==CTRL_C_EVENT || signal==CTRL_BREAK_EVENT;}
/* Manifest filenames are portable ASCII. Reject escapes/control characters and
 * use the signed exact manifest bytes, never a guessed JSON normalization. */
static const char *string(const char *s,char *out,size_t capacity) {
    if(*s++!='"') return NULL;
    size_t n=0;
    while(*s && *s!='"') {
        if((unsigned char)*s<32 || (unsigned char)*s>126 || *s=='\\' || n+1>=capacity) return NULL;
        out[n++]=*s++;
    }
    if(*s!='"') return NULL;
    out[n]=0; return s+1;
}
static int field(const char *json,const char *name,char *out,size_t cap) {
    char pattern[80]; snprintf(pattern,sizeof(pattern),"\"%s\":",name);
    const char *s=strstr(json,pattern); if(!s || strstr(s+strlen(pattern),pattern)) return 0;
    return string(space(s+strlen(pattern)),out,cap)!=NULL;
}
static int inventory(const wchar_t *root,int *files) {
    wchar_t pattern[32768],path[32768]; WIN32_FIND_DATAW data;
    if(swprintf(pattern,32768,L"\\\\?\\%ls\\*",root)<0) return 0;
    HANDLE find=FindFirstFileW(pattern,&data); if(find==INVALID_HANDLE_VALUE) return 0;
    int ok=1;
    do {
        if(!wcscmp(data.cFileName,L".") || !wcscmp(data.cFileName,L"..")) continue;
        if(data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) {ok=0;break;}
        if(swprintf(path,32768,L"%ls\\%ls",root,data.cFileName)<0) {ok=0;break;}
        if(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) {if(!inventory(path,files)) {ok=0;break;}}
        else if(++*files>10001) {ok=0;break;}
    } while(FindNextFileW(find,&data));
    if(GetLastError()!=ERROR_NO_MORE_FILES) ok=0;
    FindClose(find); return ok;
}
static int verifyfiles(const wchar_t *root,const char *manifest) {
    const char *s=strstr(manifest,"\"files\":"); if(!s) return 0;
    s=space(s+8); if(*s++!='{') return 0; int declared=0,actual=0;
    for(;;) {
        char name[4096],expected[65],got[65]; wchar_t relative[4096],path[32768];
        s=space(s); if(*s=='}') break;
        if(!(s=string(s,name,sizeof(name))) || *space(s)!=':') return 0;
        s=space(s)+1; if(!(s=string(space(s),expected,sizeof(expected))) || !hex64(expected)) return 0;
        if(!name[0] || name[0]=='/' || strstr(name,"..") || strchr(name,':') || strchr(name,'\\')) return 0;
        if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,relative,4096)) return 0;
        for(wchar_t *p=relative;*p;p++) if(*p==L'/') *p=L'\\';
        if(swprintf(path,32768,L"%ls\\%ls",root,relative)<0 || !filehash(path,got) || strcmp(expected,got)) return 0;
        if(++declared>10000) return 0;
        s=space(s); if(*s=='}') break; if(*s++!=',') return 0;
    }
    return declared>0 && inventory(root,&actual) && actual==declared+1;
}
int wmain(void) {
    wchar_t root[32768],path[32768],target[32768],command[32768]; DWORD n=GetModuleFileNameW(NULL,root,32768);
    char active[65],keyid[65],expected[65],signature[65],got[65]; DWORD size=0,keysize=0,msize=0;
    char *pointer=NULL,*key=NULL,*manifest=NULL; int result=2,launched=0;
    if(!n || n>=32768) goto done;
    wchar_t *end=wcsrchr(root,L'\\'); if(!end) goto done; *end=0;
    end=wcsrchr(root,L'\\'); if(!end) goto done; *end=0;
    if(swprintf(path,32768,L"%ls\\active.json",root)<0 || !(pointer=readfile(path,4096,&size))) goto done;
    if(!field(pointer,"active",active,65)||!hex64(active)||!field(pointer,"key_id",keyid,65)||!hex64(keyid)||
       !field(pointer,"manifest_sha256",expected,65)||!hex64(expected)||!field(pointer,"signature",signature,65)||!hex64(signature)) goto done;
    wchar_t wid[65]; MultiByteToWideChar(CP_UTF8,0,keyid,-1,wid,65);
    if(swprintf(path,32768,L"%ls\\.launcher-state\\%ls\\snapshot.key",root,wid)<0 ||
       !(key=readfile(path,32,&keysize)) || keysize!=32) goto done;
    char *sig=strstr(pointer,"\"signature\":\""); if(!sig) goto done;
    char *after=sig+strlen("\"signature\":\"")+65;
    if(*after==',') after++; else if(sig>pointer && sig[-1]==',') sig--; else goto done;
    memmove(sig,after,strlen(after)+1);
    if(!digest((unsigned char*)pointer,(DWORD)strlen(pointer),(unsigned char*)key,32,got)||strcmp(signature,got)) goto done;
    MultiByteToWideChar(CP_UTF8,0,active,-1,wid,65);
    if(swprintf(target,32768,L"%ls\\versions\\%ls\\bundle",root,wid)<0 ||
       swprintf(path,32768,L"%ls\\version.json",target)<0 || !(manifest=readfile(path,2000000,&msize)) ||
       !digest((unsigned char*)manifest,msize,NULL,0,got)||strcmp(expected,got)||!verifyfiles(target,manifest)) goto done;
    if(swprintf(path,32768,L"%ls\\security-check.exe",target)<0) goto done;
    const wchar_t *arguments=GetCommandLineW();
    if(*arguments==L'"') {arguments++;while(*arguments && *arguments!=L'"') arguments++;if(*arguments) arguments++;}
    else while(*arguments && *arguments!=L' ' && *arguments!=L'\t') arguments++;
    if(swprintf(command,32768,L"\"%ls\"%ls",path,arguments)<0) goto done;
    STARTUPINFOW startup={0}; PROCESS_INFORMATION process={0}; startup.cb=sizeof(startup);
    startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    SetConsoleCtrlHandler(control,TRUE);
    if(!CreateProcessW(path,command,NULL,NULL,TRUE,0,NULL,NULL,&startup,&process)) goto done;
    launched=1;
    WaitForSingleObject(process.hProcess,INFINITE); DWORD code=2;
    GetExitCodeProcess(process.hProcess,&code); CloseHandle(process.hThread); CloseHandle(process.hProcess); result=(int)code;
done:
    free(pointer);free(key);free(manifest);
    if(result==2 && !launched) fputs("AI Security Runtime: launcher verification failed; reinstall the verified package.\n",stderr);
    return result;
}
