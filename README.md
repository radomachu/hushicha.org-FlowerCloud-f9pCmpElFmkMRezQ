# Supabase云同步架构：Flutter应用的数据同步策略

> 本文基于[BeeCount(蜜蜂记账)](https://github.com)项目的实际开发经验，深入探讨如何使用Supabase构建安全、高效的云端数据同步系统。

## 项目背景

[BeeCount(蜜蜂记账)](https://github.com)是一款开源、简洁、无广告的个人记账应用。所有财务数据完全由用户掌控，支持本地存储和可选的云端同步，确保数据绝对安全。

## 引言

在现代移动应用开发中，多设备数据同步已成为用户的基本需求。用户希望在手机、平板、不同设备间无缝切换，同时保持数据的一致性和安全性。BeeCount选择Supabase作为云端后台服务，不仅因为其开源特性和强大功能，更重要的是它提供了完整的数据安全保障。

## Supabase架构优势

### 开源与自主可控

* **开源透明**：完全开源的后台即服务(BaaS)解决方案
* **数据主权**：支持自建部署，数据完全可控
* **标准技术**：基于PostgreSQL，无厂商锁定风险

### 功能完整性

* **实时数据库**：基于PostgreSQL的实时数据同步
* **用户认证**：完整的身份验证和授权系统
* **文件存储**：对象存储服务，支持大文件上传
* **边缘函数**：服务端逻辑处理能力

## 同步架构设计

### 整体架构图

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Flutter App   │    │   Supabase       │    │   Other Device  │
│  (Local SQLite) │◄──►│  (PostgreSQL)    │◄──►│  (Local SQLite) │
│                 │    │  (Auth + Storage) │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───── 加密备份文件 ─────┴───── 加密备份文件 ─────┘
```

### 核心设计原则

1. **本地优先**：所有操作优先在本地完成，确保响应速度
2. **增量同步**：只同步变更数据，降低网络开销
3. **端到端加密**：敏感数据在客户端加密后上传
4. **冲突处理**：合理的冲突解决策略
5. **离线可用**：网络异常时应用仍可正常使用

## 认证系统集成

### Supabase认证配置

```
class SupabaseAuthService implements AuthService {
  final s.SupabaseClient client;
  
  SupabaseAuthService({required this.client});

  @override
  Future signInWithEmail({
    required String email,
    required String password,
  }) async {
    try {
      final response = await client.auth.signInWithPassword(
        email: email,
        password: password,
      );
      
      if (response.user != null) {
        return AuthResult.success(user: AppUser.fromSupabase(response.user!));
      } else {
        return AuthResult.failure(error: 'Login failed');
      }
    } catch (e) {
      return AuthResult.failure(error: e.toString());
    }
  }

  @override
  Future signUpWithEmail({
    required String email,
    required String password,
  }) async {
    try {
      final response = await client.auth.signUp(
        email: email,
        password: password,
      );
      
      return AuthResult.success(user: AppUser.fromSupabase(response.user!));
    } catch (e) {
      return AuthResult.failure(error: e.toString());
    }
  }

  @override
  Stream get authStateChanges {
    return client.auth.onAuthStateChange.map((data) {
      if (data.session?.user != null) {
        return AuthState.authenticated(
          user: AppUser.fromSupabase(data.session!.user)
        );
      }
      return AuthState.unauthenticated();
    });
  }
}
```

### 用户模型设计

```
class AppUser {
  final String id;
  final String email;
  final DateTime? lastSignInAt;

  const AppUser({
    required this.id,
    required this.email,
    this.lastSignInAt,
  });

  factory AppUser.fromSupabase(s.User user) {
    return AppUser(
      id: user.id,
      email: user.email ?? '',
      lastSignInAt: user.lastSignInAt,
    );
  }

  bool get isAnonymous => email.isEmpty;
}
```

## 数据同步策略

### 备份文件格式

BeeCount采用加密备份文件的方式进行数据同步：

```
class BackupData {
  final String version;
  final DateTime createdAt;
  final String deviceId;
  final Map<String, dynamic> ledgers;
  final Map<String, dynamic> accounts;
  final Map<String, dynamic> categories;
  final Map<String, dynamic> transactions;
  
  BackupData({
    required this.version,
    required this.createdAt,
    required this.deviceId,
    required this.ledgers,
    required this.accounts,
    required this.categories,
    required this.transactions,
  });

  Map<String, dynamic> toJson() => {
    'version': version,
    'createdAt': createdAt.toIso8601String(),
    'deviceId': deviceId,
    'ledgers': ledgers,
    'accounts': accounts,
    'categories': categories,
    'transactions': transactions,
  };

  factory BackupData.fromJson(Map<String, dynamic> json) {
    return BackupData(
      version: json['version'],
      createdAt: DateTime.parse(json['createdAt']),
      deviceId: json['deviceId'],
      ledgers: json['ledgers'],
      accounts: json['accounts'],
      categories: json['categories'],
      transactions: json['transactions'],
    );
  }
}
```

### 同步服务实现

```
class SupabaseSyncService implements SyncService {
  final s.SupabaseClient client;
  final BeeDatabase db;
  final BeeRepository repo;
  final AuthService auth;
  final String bucket;
  
  // 状态缓存和上传窗口管理
  final Map<int, SyncStatus> _statusCache = {};
  final Map<int, _RecentUpload> _recentUpload = {};
  final Map<int, DateTime> _recentLocalChangeAt = {};

  SupabaseSyncService({
    required this.client,
    required this.db,
    required this.repo,
    required this.auth,
    this.bucket = 'beecount-backups',
  });

  @override
  Future getSyncStatus(int ledgerId) async {
    // 检查缓存
    if (_statusCache.containsKey(ledgerId)) {
      final cached = _statusCache[ledgerId]!;
      if (DateTime.now().difference(cached.lastCheck).inMinutes < 5) {
        return cached;
      }
    }

    try {
      final user = await auth.getCurrentUser();
      if (user == null) {
        return SyncStatus.notLoggedIn();
      }

      // 获取云端文件信息
      final fileName = 'ledger_${ledgerId}_backup.json';
      final cloudFile = await _getCloudFileInfo(fileName);
      
      // 计算本地数据指纹
      final localFingerprint = await _calculateLocalFingerprint(ledgerId);
      
      if (cloudFile == null) {
        final status = SyncStatus.localOnly(
          localFingerprint: localFingerprint,
          hasLocalChanges: true,
        );
        _statusCache[ledgerId] = status;
        return status;
      }

      // 比较指纹判断同步状态
      final isUpToDate = localFingerprint == cloudFile.fingerprint;
      final status = SyncStatus.synced(
        localFingerprint: localFingerprint,
        cloudFingerprint: cloudFile.fingerprint,
        isUpToDate: isUpToDate,
        lastSyncAt: cloudFile.lastModified,
      );
      
      _statusCache[ledgerId] = status;
      return status;
    } catch (e) {
      logger.error('Failed to get sync status', e);
      return SyncStatus.error(error: e.toString());
    }
  }

  @override
  Future uploadBackup(int ledgerId) async {
    try {
      final user = await auth.getCurrentUser();
      if (user == null) {
        return SyncResult.failure(error: 'Not logged in');
      }

      // 生成备份数据
      final backupData = await _generateBackup(ledgerId);
      final jsonString = json.encode(backupData.toJson());
      
      // 加密备份数据
      final encryptedData = await _encryptBackupData(jsonString);
      
      // 上传到Supabase Storage
      final fileName = 'ledger_${ledgerId}_backup.json';
      final uploadResult = await client.storage
          .from(bucket)
          .uploadBinary(fileName, encryptedData);

      if (uploadResult.isNotEmpty) {
        // 记录上传成功
        final fingerprint = await _calculateLocalFingerprint(ledgerId);
        _recentUpload[ledgerId] = _RecentUpload(
          fingerprint: fingerprint,
          uploadedAt: DateTime.now(),
        );
        
        // 更新缓存
        _statusCache[ledgerId] = SyncStatus.synced(
          localFingerprint: fingerprint,
          cloudFingerprint: fingerprint,
          isUpToDate: true,
          lastSyncAt: DateTime.now(),
        );

        return SyncResult.success(
          syncedAt: DateTime.now(),
          message: 'Backup uploaded successfully',
        );
      }

      return SyncResult.failure(error: 'Upload failed');
    } catch (e) {
      logger.error('Failed to upload backup', e);
      return SyncResult.failure(error: e.toString());
    }
  }

  @override
  Future downloadRestore(int ledgerId) async {
    try {
      final user = await auth.getCurrentUser();
      if (user == null) {
        return SyncResult.failure(error: 'Not logged in');
      }

      // 下载备份文件
      final fileName = 'ledger_${ledgerId}_backup.json';
      final downloadData = await client.storage
          .from(bucket)
          .download(fileName);

      if (downloadData.isEmpty) {
        return SyncResult.failure(error: 'No backup found');
      }

      // 解密备份数据
      final decryptedData = await _decryptBackupData(downloadData);
      final backupData = BackupData.fromJson(json.decode(decryptedData));

      // 执行数据恢复
      await _restoreFromBackup(backupData, ledgerId);

      // 更新状态
      final fingerprint = await _calculateLocalFingerprint(ledgerId);
      _statusCache[ledgerId] = SyncStatus.synced(
        localFingerprint: fingerprint,
        cloudFingerprint: fingerprint,
        isUpToDate: true,
        lastSyncAt: DateTime.now(),
      );

      return SyncResult.success(
        syncedAt: DateTime.now(),
        message: 'Data restored successfully',
      );
    } catch (e) {
      logger.error('Failed to download restore', e);
      return SyncResult.failure(error: e.toString());
    }
  }

  // 数据加密/解密
  Future _encryptBackupData(String jsonData) async {
    final key = await _getDerivedKey();
    final cipher = AESCipher(key);
    return cipher.encrypt(utf8.encode(jsonData));
  }

  Future<String> _decryptBackupData(Uint8List encryptedData) async {
    final key = await _getDerivedKey();
    final cipher = AESCipher(key);
    final decrypted = cipher.decrypt(encryptedData);
    return utf8.decode(decrypted);
  }
}
```

## 数据安全保障

### 端到端加密

```
class AESCipher {
  final Uint8List key;

  AESCipher(this.key);

  Uint8List encrypt(List<int> plaintext) {
    final cipher = AESEngine()
      ..init(true, KeyParameter(key));
    
    // 生成随机IV
    final iv = _generateRandomIV();
    final cbcCipher = CBCBlockCipher(cipher)
      ..init(true, ParametersWithIV(KeyParameter(key), iv));

    // PKCS7填充
    final paddedPlaintext = _padPKCS7(Uint8List.fromList(plaintext));
    final ciphertext = Uint8List(paddedPlaintext.length);
    
    for (int i = 0; i < paddedPlaintext.length; i += 16) {
      cbcCipher.processBlock(paddedPlaintext, i, ciphertext, i);
    }

    // IV + 密文
    return Uint8List.fromList([...iv, ...ciphertext]);
  }

  Uint8List decrypt(Uint8List encrypted) {
    // 分离IV和密文
    final iv = encrypted.sublist(0, 16);
    final ciphertext = encrypted.sublist(16);

    final cipher = AESEngine()
      ..init(false, KeyParameter(key));
    final cbcCipher = CBCBlockCipher(cipher)
      ..init(false, ParametersWithIV(KeyParameter(key), iv));

    final decrypted = Uint8List(ciphertext.length);
    for (int i = 0; i < ciphertext.length; i += 16) {
      cbcCipher.processBlock(ciphertext, i, decrypted, i);
    }

    // 移除PKCS7填充
    return _removePKCS7Padding(decrypted);
  }

  Uint8List _generateRandomIV() {
    final random = Random.secure();
    return Uint8List.fromList(
      List.generate(16, (_) => random.nextInt(256))
    );
  }
}
```

### 密钥派生

```
Future _getDerivedKey() async {
  final user = await auth.getCurrentUser();
  if (user == null) throw Exception('User not authenticated');

  // 使用用户ID和设备特征生成密钥
  final salt = utf8.encode('${user.id}_${await _getDeviceId()}');
  final password = utf8.encode(user.id);

  // PBKDF2密钥派生
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 10000, 32));

  return pbkdf2.process(password);
}

Future<String> _getDeviceId() async {
  final prefs = await SharedPreferences.getInstance();
  String? deviceId = prefs.getString('device_id');
  
  if (deviceId == null) {
    deviceId = const Uuid().v4();
    await prefs.setString('device_id', deviceId);
  }
  
  return deviceId;
}
```

## 冲突处理策略

### 冲突检测

```
class ConflictDetector {
  static ConflictResolution detectConflict({
    required BackupData localData,
    required BackupData cloudData,
    required DateTime lastSyncAt,
  }) {
    final localChanges = <String, dynamic>{};
    final cloudChanges = <String, dynamic>{};
    
    // 检测交易记录冲突
    _detectTransactionConflicts(
      localData.transactions,
      cloudData.transactions,
      lastSyncAt,
      localChanges,
      cloudChanges,
    );

    if (localChanges.isEmpty && cloudChanges.isEmpty) {
      return ConflictResolution.noConflict();
    }

    if (localChanges.isNotEmpty && cloudChanges.isEmpty) {
      return ConflictResolution.localWins(changes: localChanges);
    }

    if (localChanges.isEmpty && cloudChanges.isNotEmpty) {
      return ConflictResolution.cloudWins(changes: cloudChanges);
    }

    // 存在双向冲突，需要用户选择
    return ConflictResolution.needsResolution(
      localChanges: localChanges,
      cloudChanges: cloudChanges,
    );
  }

  static void _detectTransactionConflicts(
    Map<String, dynamic> localTxs,
    Map<String, dynamic> cloudTxs,
    DateTime lastSyncAt,
    Map<String, dynamic> localChanges,
    Map<String, dynamic> cloudChanges,
  ) {
    // 检测本地新增/修改的交易
    localTxs.forEach((id, localTx) {
      final txUpdatedAt = DateTime.parse(localTx['updatedAt'] ?? localTx['createdAt']);
      if (txUpdatedAt.isAfter(lastSyncAt)) {
        localChanges[id] = localTx;
      }
    });

    // 检测云端新增/修改的交易
    cloudTxs.forEach((id, cloudTx) {
      final txUpdatedAt = DateTime.parse(cloudTx['updatedAt'] ?? cloudTx['createdAt']);
      if (txUpdatedAt.isAfter(lastSyncAt)) {
        cloudChanges[id] = cloudTx;
      }
    });
  }
}
```

### 冲突解决

```
class ConflictResolver {
  static Future resolveConflict({
    required BackupData localData,
    required BackupData cloudData,
    required ConflictResolution resolution,
  }) async {
    switch (resolution.type) {
      case ConflictType.noConflict:
        return localData;
      
      case ConflictType.localWins:
        return localData;
      
      case ConflictType.cloudWins:
        return cloudData;
      
      case ConflictType.needsResolution:
        return await _mergeData(localData, cloudData, resolution);
    }
  }

  static Future _mergeData(
    BackupData localData,
    BackupData cloudData,
    ConflictResolution resolution,
  ) async {
    // 实现智能合并策略
    final mergedTransactions = <String, dynamic>{};
    
    // 优先保留较新的数据
    mergedTransactions.addAll(cloudData.transactions);
    
    resolution.localChanges.forEach((id, localTx) {
      final localUpdatedAt = DateTime.parse(localTx['updatedAt'] ?? localTx['createdAt']);
      
      if (resolution.cloudChanges.containsKey(id)) {
        final cloudTx = resolution.cloudChanges[id];
        final cloudUpdatedAt = DateTime.parse(cloudTx['updatedAt'] ?? cloudTx['createdAt']);
        
        // 保留时间戳较新的版本
        if (localUpdatedAt.isAfter(cloudUpdatedAt)) {
          mergedTransactions[id] = localTx;
        } else {
          mergedTransactions[id] = cloudTx;
        }
      } else {
        mergedTransactions[id] = localTx;
      }
    });

    return BackupData(
      version: localData.version,
      createdAt: DateTime.now(),
      deviceId: localData.deviceId,
      ledgers: localData.ledgers,
      accounts: localData.accounts,
      categories: localData.categories,
      transactions: mergedTransactions,
    );
  }
}
```

## 性能优化

### 增量同步优化

```
class IncrementalSync {
  static Future generateIncrementalBackup({
    required int ledgerId,
    required DateTime lastSyncAt,
    required BeeRepository repo,
  }) async {
    // 只获取自上次同步后的变更数据
    final changedTransactions = await repo.getTransactionsSince(
      ledgerId: ledgerId,
      since: lastSyncAt,
    );

    final changedAccounts = await repo.getAccountsSince(
      ledgerId: ledgerId,
      since: lastSyncAt,
    );

    // 构建增量备份数据
    return BackupData(
      version: '1.0',
      createdAt: DateTime.now(),
      deviceId: await _getDeviceId(),
      ledgers: {}, // 账本信息变化较少，可按需包含
      accounts: _mapAccountsToJson(changedAccounts),
      categories: {}, // 分类变化较少，可按需包含
      transactions: _mapTransactionsToJson(changedTransactions),
    );
  }

  static Map<String, dynamic> _mapTransactionsToJson(List transactions) {
    return Map.fromEntries(
      transactions.map((tx) => MapEntry(
        tx.id.toString(),
        {
          'id': tx.id,
          'ledgerId': tx.ledgerId,
          'type': tx.type,
          'amount': tx.amount,
          'categoryId': tx.categoryId,
          'accountId': tx.accountId,
          'toAccountId': tx.toAccountId,
          'happenedAt': tx.happenedAt.toIso8601String(),
          'note': tx.note,
          'updatedAt': DateTime.now().toIso8601String(),
        }
      ))
    );
  }
}
```

### 网络优化

```
class NetworkOptimizer {
  static const int maxRetries = 3;
  static const Duration retryDelay = Duration(seconds: 2);

  static Future withRetry(Future Function() operation) async {
    int attempts = 0;
    
    while (attempts < maxRetries) {
      try {
        return await operation();
      } catch (e) {
        attempts++;
        
        if (attempts >= maxRetries) {
          rethrow;
        }
        
        // 指数退避
        await Future.delayed(retryDelay * (1 << attempts));
      }
    }
    
    throw Exception('Max retries exceeded');
  }

  static Future<bool> isNetworkAvailable() async {
    try {
      final result = await InternetAddress.lookup('supabase.co');
      return result.isNotEmpty && result[0].rawAddress.isNotEmpty;
    } catch (_) {
      return false;
    }
  }
}
```

## 用户体验设计

### 同步状态展示

```
class SyncStatusWidget extends ConsumerWidget {
  final int ledgerId;

  const SyncStatusWidget({Key? key, required this.ledgerId}) : super(key: key);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final syncStatus = ref.watch(syncStatusProvider(ledgerId));

    return syncStatus.when(
      data: (status) => _buildStatusIndicator(status),
      loading: () => const SyncLoadingIndicator(),
      error: (error, _) => SyncErrorIndicator(error: error.toString()),
    );
  }

  Widget _buildStatusIndicator(SyncStatus status) {
    switch (status.type) {
      case SyncStatusType.synced:
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.cloud_done, color: Colors.green, size: 16),
            SizedBox(width: 4),
            Text('已同步', style: TextStyle(fontSize: 12, color: Colors.green)),
          ],
        );
      
      case SyncStatusType.localOnly:
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.cloud_off, color: Colors.orange, size: 16),
            SizedBox(width: 4),
            Text('仅本地', style: TextStyle(fontSize: 12, color: Colors.orange)),
          ],
        );
      
      case SyncStatusType.needsUpload:
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.cloud_upload, color: Colors.blue, size: 16),
            SizedBox(width: 4),
            Text('待上传', style: TextStyle(fontSize: 12, color: Colors.blue)),
          ],
        );
      
      case SyncStatusType.needsDownload:
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.cloud_download, color: Colors.purple, size: 16),
            SizedBox(width: 4),
            Text('有更新', style: TextStyle(fontSize: 12, color: Colors.purple)),
          ],
        );
      
      default:
        return SizedBox.shrink();
    }
  }
}
```

### 同步操作界面

```
class SyncActionsSheet extends ConsumerWidget {
  final int ledgerId;

  const SyncActionsSheet({Key? key, required this.ledgerId}) : super(key: key);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final syncStatus = ref.watch(syncStatusProvider(ledgerId));

    return DraggableScrollableSheet(
      initialChildSize: 0.4,
      minChildSize: 0.2,
      maxChildSize: 0.8,
      builder: (context, scrollController) {
        return Container(
          decoration: BoxDecoration(
            color: Theme.of(context).scaffoldBackgroundColor,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              // 拖拽指示器
              Container(
                width: 40,
                height: 4,
                margin: EdgeInsets.symmetric(vertical: 12),
                decoration: BoxDecoration(
                  color: Colors.grey[300],
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              
              // 标题
              Text(
                '云端同步',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              
              Expanded(
                child: ListView(
                  controller: scrollController,
                  padding: EdgeInsets.all(16),
                  children: [
                    _buildSyncActions(context, ref, syncStatus),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildSyncActions(BuildContext context, WidgetRef ref, AsyncValue syncStatus) {
    return syncStatus.when(
      data: (status) {
        switch (status.type) {
          case SyncStatusType.localOnly:
            return Column(
              children: [
                _buildActionCard(
                  title: '上传备份',
                  subtitle: '将本地数据上传到云端',
                  icon: Icons.cloud_upload,
                  color: Colors.blue,
                  onTap: () => _uploadBackup(ref),
                ),
              ],
            );
          
          case SyncStatusType.needsDownload:
            return Column(
              children: [
                _buildActionCard(
                  title: '下载恢复',
                  subtitle: '从云端恢复数据（会覆盖本地数据）',
                  icon: Icons.cloud_download,
                  color: Colors.purple,
                  onTap: () => _downloadRestore(context, ref),
                ),
                SizedBox(height: 16),
                _buildActionCard(
                  title: '强制上传',
                  subtitle: '用本地数据覆盖云端备份',
                  icon: Icons.upload,
                  color: Colors.orange,
                  onTap: () => _forceUpload(context, ref),
                ),
              ],
            );
          
          default:
            return _buildSyncInfo(status);
        }
      },
      loading: () => Center(child: CircularProgressIndicator()),
      error: (error, _) => Text('错误: $error'),
    );
  }

  Widget _buildActionCard({
    required String title,
    required String subtitle,
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    return Card(
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: color.withOpacity(0.1),
          child: Icon(icon, color: color),
        ),
        title: Text(title),
        subtitle: Text(subtitle),
        trailing: Icon(Icons.arrow_forward_ios, size: 16),
        onTap: onTap,
      ),
    );
  }
}
```

## 最佳实践总结

### 1. 架构设计原则

* **本地优先**：确保应用离线可用
* **渐进式同步**：支持部分同步，不影响核心功能
* **状态透明**：让用户清楚了解同步状态

### 2. 安全性考虑

* **端到端加密**：敏感数据客户端加密
* **密钥管理**：使用安全的密钥派生和存储
* **权限控制**：确保用户只能访问自己的数据

### 3. 性能优化

* **增量同步**：只传输变更数据
* **压缩上传**：减少网络传输量
* **后台同步**：不影响用户操作

### 4. 用户体验

* **状态可见**：清晰的同步状态指示
* **操作简单**：一键同步，自动处理
* **错误友好**：明确的错误提示和恢复建议

## 实际应用效果

在BeeCount项目中，Supabase云同步系统带来了显著的价值：

1. **用户满意度提升**：多设备无缝切换，用户数据永不丢失
2. **技术债务减少**：基于成熟的BaaS服务，减少自建后台成本
3. **安全性保障**：端到端加密确保财务数据安全
4. **开发效率**：快速集成，专注业务逻辑开发

## 结语

Supabase作为开源的BaaS解决方案，为Flutter应用提供了完整的后端服务能力。通过合理的架构设计、安全的加密策略和良好的用户体验设计，我们可以构建出既安全又好用的云同步功能。

BeeCount的实践证明，选择合适的技术栈和设计模式，能够在保证数据安全的前提下，为用户提供便捷的多设备同步体验。这对于任何需要数据同步的应用都具有重要的参考价值。

## 关于BeeCount项目

### 项目特色

* 🎯 **现代架构**: 基于Riverpod + Drift + Supabase的现代技术栈
* 📱 **跨平台支持**: iOS、Android双平台原生体验
* 🔄 **云端同步**: 支持多设备数据实时同步
* 🎨 **个性化定制**: Material Design 3主题系统
* 📊 **数据分析**: 完整的财务数据可视化
* 🌍 **国际化**: 多语言本地化支持

### 技术栈一览

* **框架**: Flutter 3.6.1+ / Dart 3.6.1+
* **状态管理**: Flutter Riverpod 2.5.1
* **数据库**: Drift (SQLite) 2.20.2
* **云服务**: Supabase 2.5.6
* **图表**: FL Chart 0.68.0
* **CI/CD**: GitHub Actions

### 开源信息

BeeCount是一个完全开源的项目，欢迎开发者参与贡献：

* **项目主页**: [https://github.com/TNT-Likely/BeeCount](https://github.com)
* **开发者主页**: [https://github.com/TNT-Likely](https://github.com)
* **发布下载**: [GitHub Releases](https://github.com):[wgetcloud](https://changshuaijiao.org)

## 参考资源

### 官方文档

* [Supabase官方文档](https://github.com) - Supabase完整使用指南
* [Flutter加密指南](https://github.com) - Flutter安全开发实践

### 学习资源

* [Supabase Flutter教程](https://github.com) - 官方Flutter集成教程
* [数据同步最佳实践](https://github.com) - 实时数据同步案例

---

*本文是BeeCount技术文章系列的第3篇，后续将深入探讨主题系统、数据可视化等话题。如果你觉得这篇文章有帮助，欢迎关注项目并给个Star！*
