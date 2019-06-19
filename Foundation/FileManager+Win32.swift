// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2019 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//

import CoreFoundation

#if os(Windows)

internal func joinPath(prefix: String, suffix: String) throws -> String {
    var pszPath: PWSTR?
    guard S_OK == (try FileManager.default._fileSystemRepresentation(withPath: prefix, andPath: suffix) {
        PathAllocCombine($0, $1, ULONG(PATHCCH_ALLOW_LONG_PATHS.rawValue), &pszPath)
    }) else {
        throw _windowsErrorToNSError(error: GetLastError(), paths: [prefix], reading: false)
    }

    let path: String = String(decodingCString: pszPath!, as: UTF16.self)
    LocalFree(pszPath)
    return path
}

internal func _windowsErrorToNSError(error: DWORD, paths: [String], reading: Bool) -> NSError {
    // On an empty path, Windows will return path not found rather than invalid
    // path as posix does
    if let emptyPath = paths.first(where: { $0.isEmpty }) {
        return NSError(domain: NSCocoaErrorDomain,
                       code: CocoaError.fileReadInvalidFileName.rawValue,
                       userInfo: [NSFilePathErrorKey : NSString(emptyPath)])
    }
    return _NSErrorWithWindowsError(GetLastError(), reading: reading)
}

extension FileManager {
    internal func _mountedVolumeURLs(includingResourceValuesForKeys propertyKeys: [URLResourceKey]?, options: VolumeEnumerationOptions = []) -> [URL]? {
        var urls: [URL] = []

        var wszVolumeName: [WCHAR] = Array<WCHAR>(repeating: 0, count: Int(MAX_PATH))

        var hVolumes: HANDLE = FindFirstVolumeW(&wszVolumeName, DWORD(wszVolumeName.count))
        guard hVolumes != INVALID_HANDLE_VALUE else { return nil }
        defer { FindVolumeClose(hVolumes) }

        repeat {
            var dwCChReturnLength: DWORD = 0
            GetVolumePathNamesForVolumeNameW(&wszVolumeName, nil, 0, &dwCChReturnLength)

            var wszPathNames: [WCHAR] = Array<WCHAR>(repeating: 0, count: Int(dwCChReturnLength + 1))
            if !GetVolumePathNamesForVolumeNameW(&wszVolumeName, &wszPathNames, DWORD(wszPathNames.count), &dwCChReturnLength) {
                // TODO(compnerd) handle error
                continue
            }

            var pPath: DWORD = 0
            repeat {
                let path: String = String(decodingCString: &wszPathNames[Int(pPath)], as: UTF16.self)
                if path.length == 0 {
                    break
                }
                urls.append(URL(fileURLWithPath: path, isDirectory: true))
                pPath += DWORD(path.length + 1)
            } while pPath < dwCChReturnLength
        } while FindNextVolumeW(hVolumes, &wszVolumeName, DWORD(wszVolumeName.count))

        return urls
    }
    internal func _urls(for directory: SearchPathDirectory, in domainMask: SearchPathDomainMask) -> [URL] {
        let domains = _SearchPathDomain.allInSearchOrder(from: domainMask)

        var urls: [URL] = []

        for domain in domains {
            urls.append(contentsOf: windowsURLs(for: directory, in: domain))
        }

        return urls
    }

    private class func url(for id: KNOWNFOLDERID) -> URL {
        var pszPath: PWSTR?
        let hResult: HRESULT = withUnsafePointer(to: id) { id in
            SHGetKnownFolderPath(id, DWORD(KF_FLAG_DEFAULT.rawValue), nil, &pszPath)
        }
        precondition(hResult >= 0, "SHGetKnownFolderpath failed \(GetLastError())")
        let url: URL = URL(fileURLWithPath: String(decodingCString: pszPath!, as: UTF16.self), isDirectory: true)
        CoTaskMemFree(pszPath)
        return url
    }

    private func windowsURLs(for directory: SearchPathDirectory, in domain: _SearchPathDomain) -> [URL] {
        switch directory {
        case .autosavedInformationDirectory:
            // FIXME(compnerd) where should this go?
            return []

        case .desktopDirectory:
            guard domain == .user else { return [] }
            return [FileManager.url(for: FOLDERID_Desktop)]

        case .documentDirectory:
            guard domain == .user else { return [] }
            return [FileManager.url(for: FOLDERID_Documents)]

        case .cachesDirectory:
            guard domain == .user else { return [] }
            return [URL(fileURLWithPath: NSTemporaryDirectory())]

        case .applicationSupportDirectory:
            switch domain {
            case .local:
                return [FileManager.url(for: FOLDERID_ProgramData)]
            case .user:
                return [FileManager.url(for: FOLDERID_LocalAppData)]
            default:
                return []
            }

            case .downloadsDirectory:
                guard domain == .user else { return [] }
                return [FileManager.url(for: FOLDERID_Downloads)]

            case .userDirectory:
                guard domain == .user else { return [] }
                return [FileManager.url(for: FOLDERID_UserProfiles)]

            case .moviesDirectory:
                guard domain == .user else { return [] }
                return [FileManager.url(for: FOLDERID_Videos)]

            case .musicDirectory:
                guard domain == .user else { return [] }
                return [FileManager.url(for: FOLDERID_Music)]

            case .picturesDirectory:
                guard domain == .user else { return [] }
                return [FileManager.url(for: FOLDERID_PicturesLibrary)]

            case .sharedPublicDirectory:
                guard domain == .user else { return [] }
                return [FileManager.url(for: FOLDERID_Public)]

            case .trashDirectory:
                guard domain == .user else { return [] }
                return [FileManager.url(for: FOLDERID_RecycleBinFolder)]

                // None of these are supported outside of Darwin:
            case .applicationDirectory,
                 .demoApplicationDirectory,
                 .developerApplicationDirectory,
                 .adminApplicationDirectory,
                 .libraryDirectory,
                 .developerDirectory,
                 .documentationDirectory,
                 .coreServiceDirectory,
                 .inputMethodsDirectory,
                 .preferencePanesDirectory,
                 .applicationScriptsDirectory,
                 .allApplicationsDirectory,
                 .allLibrariesDirectory,
                 .printerDescriptionDirectory,
                 .itemReplacementDirectory:
                return []
        }
    }

    internal func _createDirectory(atPath path: String, withIntermediateDirectories createIntermediates: Bool, attributes: [FileAttributeKey : Any]? = [:]) throws {
        if createIntermediates {
            var isDir: ObjCBool = false
            if fileExists(atPath: path, isDirectory: &isDir) {
                guard isDir.boolValue else { throw _NSErrorWithErrno(EEXIST, reading: false, path: path) }
                return
            }

            let parent = path._nsObject.deletingLastPathComponent
            if !parent.isEmpty && !fileExists(atPath: parent, isDirectory: &isDir) {
                try createDirectory(atPath: parent, withIntermediateDirectories: true, attributes: attributes)
            }
        }

        var saAttributes: SECURITY_ATTRIBUTES =
          SECURITY_ATTRIBUTES(nLength: DWORD(MemoryLayout<SECURITY_ATTRIBUTES>.size),
                              lpSecurityDescriptor: nil,
                              bInheritHandle: false)
        let psaAttributes: UnsafeMutablePointer<SECURITY_ATTRIBUTES> =
          UnsafeMutablePointer<SECURITY_ATTRIBUTES>(&saAttributes)


        guard try _fileSystemRepresentation(withPath: path, { CreateDirectoryW($0, psaAttributes) }) else {
            throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: false)
        }
        if let attr = attributes {
            try self.setAttributes(attr, ofItemAtPath: path)
        }
    }

    internal func _contentsOfDir(atPath path: String, _ closure: (String, Int32) throws -> () ) throws {
        guard path != "" else {
            throw NSError(domain: NSCocoaErrorDomain, code: CocoaError.fileReadInvalidFileName.rawValue, userInfo: [NSFilePathErrorKey : NSString(path)])
        }
        try _fileSystemRepresentation(withPath: path + "\\*") {
            var ffd: WIN32_FIND_DATAW = WIN32_FIND_DATAW()

            let hDirectory: HANDLE = FindFirstFileW($0, &ffd)
            if hDirectory == INVALID_HANDLE_VALUE {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
            }
            defer { FindClose(hDirectory) }

            repeat {
                let path: String = withUnsafePointer(to: &ffd.cFileName) {
                    $0.withMemoryRebound(to: UInt16.self, capacity: MemoryLayout.size(ofValue: $0) / MemoryLayout<WCHAR>.size) {
                        String(decodingCString: $0, as: UTF16.self)
                    }
                }
                if path != "." && path != ".." {
                    try closure(path, Int32(ffd.dwFileAttributes))
                }
            } while FindNextFileW(hDirectory, &ffd)
        }
    }

    internal func _subpathsOfDirectory(atPath path: String) throws -> [String] {
        var contents: [String] = []

        try _contentsOfDir(atPath: path, { (entryName, entryType) throws in
            contents.append(entryName)
            if entryType & FILE_ATTRIBUTE_DIRECTORY == FILE_ATTRIBUTE_DIRECTORY {
                let subPath: String = try joinPath(prefix: path, suffix: entryName)
                let entries = try subpathsOfDirectory(atPath: subPath)
                contents.append(contentsOf: try entries.map { try joinPath(prefix: entryName, suffix: $0) })
            }
        })
        return contents
    }

    internal func windowsFileAttributes(atPath path: String) throws -> WIN32_FILE_ATTRIBUTE_DATA {
        var faAttributes: WIN32_FILE_ATTRIBUTE_DATA = WIN32_FILE_ATTRIBUTE_DATA()
        return try _fileSystemRepresentation(withPath: path) {
            if !GetFileAttributesExW($0, GetFileExInfoStandard, &faAttributes) {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
            }
            return faAttributes
        }
    }
    
    internal func _attributesOfFileSystemIncludingBlockSize(forPath path: String) throws -> (attributes: [FileAttributeKey : Any], blockSize: UInt64?) {
        return (attributes: try _attributesOfFileSystem(forPath: path), blockSize: nil)
    }

    internal func _attributesOfFileSystem(forPath path: String) throws -> [FileAttributeKey : Any] {
        var result: [FileAttributeKey:Any] = [:]

        try _fileSystemRepresentation(withPath: path) {
            let dwLength: DWORD = GetFullPathNameW($0, 0, nil, nil)
            guard dwLength != 0 else {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
            }
            var szVolumePath: [WCHAR] = Array<WCHAR>(repeating: 0, count: Int(dwLength + 1))

            guard GetVolumePathNameW($0, &szVolumePath, dwLength) else {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
            }

            var liTotal: ULARGE_INTEGER = ULARGE_INTEGER()
            var liFree: ULARGE_INTEGER = ULARGE_INTEGER()

            guard GetDiskFreeSpaceExW(&szVolumePath, nil, &liTotal, &liFree) else {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
            }

            var volumeSerialNumber: DWORD = 0
            guard GetVolumeInformationW(&szVolumePath, nil, 0, &volumeSerialNumber, nil, nil, nil, 0) else {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
            }

            result[.systemSize] = NSNumber(value: liTotal.QuadPart)
            result[.systemFreeSize] = NSNumber(value: liFree.QuadPart)
            result[.systemNumber] = NSNumber(value: volumeSerialNumber)
            // FIXME(compnerd): what about .systemNodes, .systemFreeNodes?
        }
        return result
    }

    internal func _createSymbolicLink(atPath path: String, withDestinationPath destPath: String) throws {
        var dwFlags = DWORD(SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)
        // Note: windowsfileAttributes will throw if the destPath is not found.
        // Since on Windows, you are required to know the type of the symlink
        // target (file or directory) during creation, and assuming one or the
        // other doesn't make a lot of sense, we allow it to throw, thus
        // disallowing the creation of broken symlinks on Windows (unlike with
        // POSIX).
        guard let faAttributes = try? windowsFileAttributes(atPath: destPath) else {
            throw _windowsErrorToNSError(error: GetLastError(), paths: [path, destPath], reading: true)
        }
        if faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_DIRECTORY) == DWORD(FILE_ATTRIBUTE_DIRECTORY) {
            dwFlags |= DWORD(SYMBOLIC_LINK_FLAG_DIRECTORY)
        }

        guard try _fileSystemRepresentation(withPath: path, andPath: destPath, { CreateSymbolicLinkW($0, $1, dwFlags) != 0 }) else {
            throw _windowsErrorToNSError(error: GetLastError(), paths: [path, destPath], reading: true)
        }
    }

    internal func _destinationOfSymbolicLink(atPath path: String) throws -> String {
        let handle = try _fileSystemRepresentation(withPath: path) {
            CreateFileW($0,
                GENERIC_READ,
                DWORD(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
                nil,
                DWORD(OPEN_EXISTING),
                DWORD(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS),
                nil)
        }

        guard handle != INVALID_HANDLE_VALUE else {
          throw _NSErrorWithWindowsError(GetLastError(), reading: true)
        }
        defer { CloseHandle(handle) }

        // Since REPARSE_DATA_BUFFER ends with an arbitrarily long buffer, we
        // have to manually get the path buffer out of it since binding it to a
        // type will truncate the path buffer
        let pathBufferOffset =
            MemoryLayout<ULONG>.size //ULONG ReparseTag
            + MemoryLayout<USHORT>.size //ULONG ReparseDataLength
            + MemoryLayout<USHORT>.size //ULONG Reserved
            + MemoryLayout<USHORT>.size //ULONG SubstituteNameOffset
            + MemoryLayout<USHORT>.size //ULONG SubstituteNameLength
            + MemoryLayout<USHORT>.size //ULONG PrintNameOffset
            + MemoryLayout<USHORT>.size //ULONG PrintNameLength
            + MemoryLayout<ULONG>.size //ULONG Flags

        var buff = Array(repeating: 0, count: MemoryLayout<REPARSE_DATA_BUFFER>.size + Int(2 * MAX_PATH))

        return try buff.withUnsafeMutableBytes {
          var bytesWritten: DWORD = 0
          guard DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, nil, 0,
              $0.baseAddress, DWORD($0.count), &bytesWritten, nil) else {
            throw _NSErrorWithWindowsError(GetLastError(), reading: true)
          }

          let bound = $0.bindMemory(to: REPARSE_DATA_BUFFER.self)
          guard let reparseDataBuffer = bound.first else {
            fatalError()
          }

          let pathBufferPtr = $0.baseAddress! + pathBufferOffset
          let printNameBytes = Int(reparseDataBuffer.SymbolicLinkReparseBuffer.PrintNameLength)
          let printNameOffset = Int(reparseDataBuffer.SymbolicLinkReparseBuffer.PrintNameOffset)
          let printNameBuff = Data(bytes: pathBufferPtr + printNameOffset, count: printNameBytes)
          guard let printPath = String(data: printNameBuff, encoding: .utf16LittleEndian) else {
            fatalError()
          }
          return printPath
        }
    }

    internal func _canonicalizedPath(toFileAtPath path: String) throws -> String {
        var hFile: HANDLE = try _fileSystemRepresentation(withPath: path) {
            // BACKUP_SEMANTICS are (confusingly) required in order to receive a
            // handle to a directory
            CreateFileW($0, 0, DWORD(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
                        nil, DWORD(OPEN_EXISTING), DWORD(FILE_FLAG_BACKUP_SEMANTICS),
                        nil)
        }
        guard hFile != INVALID_HANDLE_VALUE else {
            return try _fileSystemRepresentation(withPath: path) {
                var dwLength = GetFullPathNameW($0, 0, nil, nil)
                var szPath = Array<WCHAR>(repeating: 0, count: Int(dwLength + 1))
                dwLength = GetFullPathNameW($0, DWORD(szPath.count), &szPath, nil)
                guard dwLength > 0 && dwLength <= szPath.count else {
                    throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
                }
                return String(decodingCString: szPath, as: UTF16.self)
            }
        }
        defer { CloseHandle(hFile) }

        let dwLength: DWORD = GetFinalPathNameByHandleW(hFile, nil, 0, DWORD(FILE_NAME_NORMALIZED))
        var szPath: [WCHAR] = Array<WCHAR>(repeating: 0, count: Int(dwLength + 1))

        GetFinalPathNameByHandleW(hFile, &szPath, dwLength, DWORD(FILE_NAME_NORMALIZED))
        return String(decodingCString: &szPath, as: UTF16.self)
    }

    internal func _copyRegularFile(atPath srcPath: String, toPath dstPath: String, variant: String = "Copy") throws {
        guard try _fileSystemRepresentation(withPath: srcPath, andPath: dstPath, { CopyFileW($0, $1, false) }) else {
            throw _windowsErrorToNSError(error: GetLastError(), paths: [srcPath, dstPath], reading: true)
        }
    }

    internal func _copySymlink(atPath srcPath: String, toPath dstPath: String, variant: String = "Copy") throws {
        let faAttributes: WIN32_FILE_ATTRIBUTE_DATA = try windowsFileAttributes(atPath: srcPath)
        guard faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_REPARSE_POINT) == DWORD(FILE_ATTRIBUTE_REPARSE_POINT) else {
            throw _NSErrorWithErrno(EINVAL, reading: true, path: srcPath, extraUserInfo: extraErrorInfo(srcPath: srcPath, dstPath: dstPath, userVariant: variant))
        }

        let destination = try FileManager.default.destinationOfSymbolicLink(atPath: srcPath)

        var dwFlags: DWORD = DWORD(SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)
        if try windowsFileAttributes(atPath: destination).dwFileAttributes & DWORD(FILE_ATTRIBUTE_DIRECTORY) == DWORD(FILE_ATTRIBUTE_DIRECTORY) {
            dwFlags |= DWORD(SYMBOLIC_LINK_FLAG_DIRECTORY)
        }

        try FileManager.default.createSymbolicLink(atPath: dstPath, withDestinationPath: destination)
    }

    internal func _copyOrLinkDirectoryHelper(atPath srcPath: String, toPath dstPath: String, variant: String = "Copy", _ body: (String, String, FileAttributeType) throws -> ()) throws {
        let faAttributes = try windowsFileAttributes(atPath: srcPath)

        var fileType = FileAttributeType(attributes: faAttributes, atPath: srcPath)
        if fileType == .typeDirectory {
          try createDirectory(atPath: dstPath, withIntermediateDirectories: false, attributes: nil)
          guard let enumerator = enumerator(atPath: srcPath) else {
            throw _NSErrorWithErrno(ENOENT, reading: true, path: srcPath)
          }

          while let item = enumerator.nextObject() as? String {
            let src = try joinPath(prefix: srcPath, suffix: item)
            let dst = try joinPath(prefix: dstPath, suffix: item)

            let faAttributes = try windowsFileAttributes(atPath: src)
            fileType = FileAttributeType(attributes: faAttributes, atPath: srcPath)
            if fileType == .typeDirectory {
              try createDirectory(atPath: dst, withIntermediateDirectories: false, attributes: nil)
            } else {
              try body(src, dst, fileType)
            }
          }
        } else {
          try body(srcPath, dstPath, fileType)
        }
    }

    internal func _moveItem(atPath srcPath: String, toPath dstPath: String, isURL: Bool) throws {
        guard shouldMoveItemAtPath(srcPath, toPath: dstPath, isURL: isURL) else {
            return
        }

        guard !self.fileExists(atPath: dstPath) else {
            throw NSError(domain: NSCocoaErrorDomain, code: CocoaError.fileWriteFileExists.rawValue, userInfo: [NSFilePathErrorKey : NSString(dstPath)])
        }

        guard try _fileSystemRepresentation(withPath: srcPath, andPath: dstPath, {
            MoveFileExW($0, $1, DWORD(MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH))
        }) else {
            throw _windowsErrorToNSError(error: GetLastError(), paths: [srcPath, dstPath], reading: false)
        }
    }

    internal func _linkItem(atPath srcPath: String, toPath dstPath: String, isURL: Bool) throws {
        try _copyOrLinkDirectoryHelper(atPath: srcPath, toPath: dstPath) { (srcPath, dstPath, fileType) in
            guard shouldLinkItemAtPath(srcPath, toPath: dstPath, isURL: isURL) else {
                return
            }

            do {
                switch fileType {
                case .typeRegular:
                    guard try _fileSystemRepresentation(withPath: srcPath, andPath: dstPath, { CreateHardLinkW($1, $0, nil) }) else {
                        throw _windowsErrorToNSError(error: GetLastError(), paths: [srcPath, dstPath], reading: false)
                    }
                case .typeSymbolicLink:
                    try _copySymlink(atPath: srcPath, toPath: dstPath)
                default:
                    break
                }
            } catch {
                if !shouldProceedAfterError(error, linkingItemAtPath: srcPath, toPath: dstPath, isURL: isURL) {
                    throw error
                }
            }
        }
    }

    internal func _removeItem(atPath path: String, isURL: Bool, alreadyConfirmed: Bool = false) throws {
        guard alreadyConfirmed || shouldRemoveItemAtPath(path, isURL: isURL) else {
            return
        }

        let faAttributes = try windowsFileAttributes(atPath: path)
        if faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_READONLY) == FILE_ATTRIBUTE_READONLY {
        let readableAttributes = faAttributes.dwFileAttributes & DWORD(bitPattern: ~FILE_ATTRIBUTE_READONLY)
            guard try _fileSystemRepresentation(withPath: path, { SetFileAttributesW($0, readableAttributes) }) else {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: false)
            }
        }

        if faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_DIRECTORY) == 0 {
            guard try _fileSystemRepresentation(withPath: path, DeleteFileW) else {
                throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: false)
            }
            return
        }
        var dirStack = [path]
        var itemPath = ""
        while let currentDir = dirStack.popLast() {
            do {
                itemPath = currentDir
                guard alreadyConfirmed || shouldRemoveItemAtPath(itemPath, isURL: isURL) else {
                    continue
                }
                guard !(try _fileSystemRepresentation(withPath: itemPath, RemoveDirectoryW)) else {
                    continue
                }
                guard GetLastError() == ERROR_DIR_NOT_EMPTY else {
                    throw _windowsErrorToNSError(error: GetLastError(), paths: [itemPath], reading: false)
                }
                dirStack.append(itemPath)
                var ffd: WIN32_FIND_DATAW = WIN32_FIND_DATAW()
                let h: HANDLE = try _fileSystemRepresentation(withPath: itemPath + "\\*", { FindFirstFileW($0, &ffd) })
                guard h != INVALID_HANDLE_VALUE else {
                    throw _windowsErrorToNSError(error: GetLastError(), paths: [itemPath], reading: false)
                }
                defer { FindClose(h) }

                repeat {
                    let fileArr = Array<WCHAR>(
                        UnsafeBufferPointer(start: &ffd.cFileName.0,
                                            count: MemoryLayout.size(ofValue: ffd.cFileName)))
                    let file = String(decodingCString: fileArr, as: UTF16.self)
                    itemPath = "\(currentDir)\\\(file)"

                    if ffd.dwFileAttributes & DWORD(FILE_ATTRIBUTE_READONLY) == FILE_ATTRIBUTE_READONLY {
                        let readableAttributes = ffd.dwFileAttributes & DWORD(bitPattern: ~FILE_ATTRIBUTE_READONLY)
                        guard try _fileSystemRepresentation(withPath: file, { SetFileAttributesW($0, readableAttributes) }) else {
                            throw _windowsErrorToNSError(error: GetLastError(), paths: [file], reading: false)
                        }
                    }

                    if (ffd.dwFileAttributes & DWORD(FILE_ATTRIBUTE_DIRECTORY) != 0) {
                        if file != "." && file != ".." {
                            dirStack.append(itemPath)
                        }
                    } else {
                        guard alreadyConfirmed || shouldRemoveItemAtPath(itemPath, isURL: isURL) else {
                            continue
                        }
                        guard try _fileSystemRepresentation(withPath: itemPath, DeleteFileW) else {
                            throw _windowsErrorToNSError(error: GetLastError(), paths: [file], reading: false)
                        }
                    }
                } while FindNextFileW(h, &ffd)
            } catch {
                if !shouldProceedAfterError(error, removingItemAtPath: itemPath, isURL: isURL) {
                    throw error
                }
            }
        }
    }

    internal func _currentDirectoryPath() -> String {
        let dwLength: DWORD = GetCurrentDirectoryW(0, nil)
        var szDirectory: [WCHAR] = Array<WCHAR>(repeating: 0, count: Int(dwLength + 1))

        GetCurrentDirectoryW(dwLength, &szDirectory)
        return String(decodingCString: &szDirectory, as: UTF16.self)
    }

    @discardableResult
    internal func _changeCurrentDirectoryPath(_ path: String) -> Bool {
        return (try? _fileSystemRepresentation(withPath: path, SetCurrentDirectoryW)) ?? false
    }

    internal func _fileExists(atPath path: String, isDirectory: UnsafeMutablePointer<ObjCBool>?) -> Bool {
        var faAttributes: WIN32_FILE_ATTRIBUTE_DATA = WIN32_FILE_ATTRIBUTE_DATA()
        do { faAttributes = try windowsFileAttributes(atPath: path) } catch { return false }
        if faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_REPARSE_POINT) == DWORD(FILE_ATTRIBUTE_REPARSE_POINT) {
            do { try faAttributes = windowsFileAttributes(atPath: destinationOfSymbolicLink(atPath: path)) } catch { return false }
        }
        if let isDirectory = isDirectory {
            isDirectory.pointee = ObjCBool(faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_DIRECTORY) == DWORD(FILE_ATTRIBUTE_DIRECTORY))
        }
        return true
    }


    internal func _isReadableFile(atPath path: String) -> Bool {
        do { let _ = try windowsFileAttributes(atPath: path) } catch { return false }
        return true
    }

    internal func _isWritableFile(atPath path: String) -> Bool {
        guard let faAttributes: WIN32_FILE_ATTRIBUTE_DATA = try? windowsFileAttributes(atPath: path) else { return false }
        return faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_READONLY) != DWORD(FILE_ATTRIBUTE_READONLY)
    }

    internal func _isExecutableFile(atPath path: String) -> Bool {
        var isDirectory: ObjCBool = false
        guard fileExists(atPath: path, isDirectory: &isDirectory) else { return false }
        return !isDirectory.boolValue && _isReadableFile(atPath: path)
    }

    internal func _isDeletableFile(atPath path: String) -> Bool {
        guard path != "" else { return true }

        // Get the parent directory of supplied path
        let parent = path._nsObject.deletingLastPathComponent
        var faAttributes: WIN32_FILE_ATTRIBUTE_DATA = WIN32_FILE_ATTRIBUTE_DATA()
        do { faAttributes = try windowsFileAttributes(atPath: parent) } catch { return false }
        if faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_READONLY) == DWORD(FILE_ATTRIBUTE_READONLY) {
            return false
        }

        do { faAttributes = try windowsFileAttributes(atPath: path) } catch { return false }
        if faAttributes.dwFileAttributes & DWORD(FILE_ATTRIBUTE_READONLY) == DWORD(FILE_ATTRIBUTE_READONLY) {
            return false
        }

        return true
    }

    internal func _compareFiles(withFileSystemRepresentation file1Rep: UnsafePointer<Int8>, andFileSystemRepresentation file2Rep: UnsafePointer<Int8>, size: Int64, bufSize: Int) -> Bool {
        NSUnimplemented()
    }

    internal func _lstatFile(atPath path: String, withFileSystemRepresentation fsRep: UnsafePointer<foundation_char_t>? = nil) throws -> stat {
        let _fsRep: UnsafePointer<foundation_char_t>
        if fsRep == nil {
            _fsRep = try __fileSystemRepresentation(withPath: path)
        } else {
            _fsRep = fsRep!
        }

        defer {
            if fsRep == nil { _fsRep.deallocate() }
        }

        var statInfo = stat()
        let h = CreateFileW(/*lpFileName=*/_fsRep,
                            /*dwDesiredAccess=*/DWORD(0),
                            /*dwShareMode=*/DWORD(FILE_SHARE_READ),
                            /*lpSecurityAttributes=*/nil,
                            /*dwCreationDisposition=*/DWORD(OPEN_EXISTING),
                            /*dwFlagsAndAttributes=*/DWORD(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS),
                            /*hTemplateFile=*/nil)
        if h == INVALID_HANDLE_VALUE {
            throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: false)
        }
        var info: BY_HANDLE_FILE_INFORMATION = BY_HANDLE_FILE_INFORMATION()
        GetFileInformationByHandle(h, &info)
        // Group id is always 0 on Windows
        statInfo.st_gid = 0
        statInfo.st_atime = info.ftLastAccessTime.time_t
        statInfo.st_ctime = info.ftCreationTime.time_t
        statInfo.st_dev = info.dwVolumeSerialNumber
        // inodes have meaning on FAT/HPFS/NTFS
        statInfo.st_ino = 0
        statInfo.st_rdev = info.dwVolumeSerialNumber

        let isReparsePoint = info.dwFileAttributes & DWORD(FILE_ATTRIBUTE_REPARSE_POINT) != 0
        let isDir = info.dwFileAttributes & DWORD(FILE_ATTRIBUTE_DIRECTORY) != 0
        let fileMode = isDir ? _S_IFDIR : _S_IFREG
        // On a symlink to a directory, Windows sets both the REPARSE_POINT and
        // DIRECTORY attributes. Since Windows doesn't provide S_IFLNK and we
        // want unix style "symlinks to directories are not directories
        // themselves, we say symlinks are regular files
        statInfo.st_mode = UInt16(isReparsePoint ? _S_IFREG : fileMode)
        let isReadOnly = info.dwFileAttributes & DWORD(FILE_ATTRIBUTE_READONLY) != 0
        statInfo.st_mode |= UInt16(isReadOnly ? _S_IREAD : (_S_IREAD | _S_IWRITE))
        statInfo.st_mode |= UInt16(_S_IEXEC)

        statInfo.st_mtime = info.ftLastWriteTime.time_t
        statInfo.st_nlink = Int16(info.nNumberOfLinks)
        if info.nFileSizeHigh != 0 {
            throw _NSErrorWithErrno(EOVERFLOW, reading: true, path: path)
        }
        statInfo.st_size = Int32(info.nFileSizeLow)
        // Uid is always 0 on Windows systems
        statInfo.st_uid = 0
        CloseHandle(h)
        return statInfo
    }

    internal func _contentsEqual(atPath path1: String, andPath path2: String) -> Bool {
        NSUnimplemented()
    }

    internal func _appendSymlinkDestination(_ dest: String, toPath: String) -> String {
        if dest.isAbsolutePath { return dest }
        let temp = toPath._bridgeToObjectiveC().deletingLastPathComponent
        return temp._bridgeToObjectiveC().appendingPathComponent(dest)
    }

    internal func _updateTimes(atPath path: String,
                               withFileSystemRepresentation fsr: UnsafePointer<foundation_char_t>,
                               creationTime: Date? = nil,
                               accessTime: Date? = nil,
                               modificationTime: Date? = nil) throws {
      let stat = try _lstatFile(atPath: path, withFileSystemRepresentation: fsr)

      var atime = FILETIME(from: time_t((accessTime ?? stat.lastAccessDate).timeIntervalSince1970))
      var mtime = FILETIME(from: time_t((modificationTime ?? stat.lastModificationDate).timeIntervalSince1970))

      let hFile = CreateFileW(fsr, DWORD(GENERIC_WRITE), DWORD(FILE_SHARE_WRITE), nil, DWORD(OPEN_EXISTING), 0, nil)
      if hFile == INVALID_HANDLE_VALUE {
          throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: true)
      }
      defer { CloseHandle(hFile) }

      if !SetFileTime(hFile, nil, &atime, &mtime) {
          throw _windowsErrorToNSError(error: GetLastError(), paths: [path], reading: false)
      }

    }

    internal class NSURLDirectoryEnumerator : DirectoryEnumerator {
        var _options : FileManager.DirectoryEnumerationOptions
        var _errorHandler : ((URL, Error) -> Bool)?
        var _stack: [URL]
        var _lastReturned: URL
        var _rootDepth : Int

        init(url: URL, options: FileManager.DirectoryEnumerationOptions, errorHandler: (/* @escaping */ (URL, Error) -> Bool)?) {
            _options = options
            _errorHandler = errorHandler
            _stack = []
            _rootDepth = url.pathComponents.count
            _lastReturned = url
        }

        override func nextObject() -> Any? {
            func firstValidItem() -> URL? {
                while let url = _stack.popLast() {
                    if !FileManager.default.fileExists(atPath: url.path, isDirectory: nil) {
                        guard let handler = _errorHandler,
                              handler(url, _windowsErrorToNSError(error: GetLastError(), paths: [url.path], reading: true))
                        else { return nil }
                        continue
                    }
                    _lastReturned = url
                    return _lastReturned
                }
                return nil
            }

            // If we most recently returned a directory, decend into it
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: _lastReturned.path, isDirectory: &isDir) else {
              guard let handler = _errorHandler,
                    handler(_lastReturned, _windowsErrorToNSError(error: GetLastError(), paths: [_lastReturned.path], reading: true))
              else { return nil }
              return firstValidItem()
            }

            if isDir.boolValue && (level == 0 || !_options.contains(.skipsSubdirectoryDescendants)) {
                var ffd = WIN32_FIND_DATAW()
                guard let dirPath = try? joinPath(prefix: _lastReturned.path, suffix: "*"),
                      let handle = try? FileManager.default._fileSystemRepresentation(withPath: dirPath, { FindFirstFileW($0, &ffd) }),
                      handle != INVALID_HANDLE_VALUE else {
                    return firstValidItem()
                }
                defer { FindClose(handle) }

                repeat {
                    let fileArr = Array<WCHAR>(
                      UnsafeBufferPointer(start: &ffd.cFileName.0,
                                          count: MemoryLayout.size(ofValue: ffd.cFileName)))
                    let file = String(decodingCString: fileArr, as: UTF16.self)
                    if file != "." && file != ".."
                        && (!_options.contains(.skipsHiddenFiles)
                            || (ffd.dwFileAttributes & DWORD(FILE_ATTRIBUTE_HIDDEN) == 0)) {
                        let relative = URL(fileURLWithPath: file, relativeTo: _lastReturned)
                        _stack.append(relative)
                    }
                } while FindNextFileW(handle, &ffd)
            }

            return firstValidItem()
        }

        override var level: Int {
            return _lastReturned.pathComponents.count - _rootDepth
        }

        override func skipDescendants() {
            _options.insert(.skipsSubdirectoryDescendants)
        }

        override var directoryAttributes : [FileAttributeKey : Any]? {
            return nil
        }

        override var fileAttributes: [FileAttributeKey : Any]? {
            return nil
        }
    }
}

extension FileManager.NSPathDirectoryEnumerator {
    internal func _nextObject() -> Any? {
        guard let url = innerEnumerator.nextObject() as? URL else { return nil }

        var relativePath: [WCHAR] = Array<WCHAR>(repeating: 0, count: Int(MAX_PATH))

        guard baseURL._withUnsafeWideFileSystemRepresentation({ baseUrlFsr in
            url._withUnsafeWideFileSystemRepresentation { urlFsr in
                let fromAttrs = GetFileAttributesW(baseUrlFsr)
                let toAttrs = GetFileAttributesW(urlFsr)
                guard fromAttrs != INVALID_FILE_ATTRIBUTES, toAttrs != INVALID_FILE_ATTRIBUTES else {
                    return false
                }
                return PathRelativePathToW(&relativePath, baseUrlFsr, fromAttrs, urlFsr, toAttrs)
            }
        }) else { return nil }

        let path = String(decodingCString: &relativePath, as: UTF16.self)
        // Drop the leading ".\" from the path
        _currentItemPath = String(path.dropFirst(2))
        return _currentItemPath
    }

}

#endif
