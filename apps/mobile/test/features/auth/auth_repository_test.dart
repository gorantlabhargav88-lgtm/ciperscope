import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mocktail/mocktail.dart';
import 'package:mobile/core/networking/api_client.dart';
import 'package:mobile/core/security/secure_storage.dart';
import 'package:mobile/features/auth/data/auth_repository.dart';
import 'package:mobile/features/auth/providers/auth_provider.dart';

class _MockFlutterSecureStorage extends Mock implements FlutterSecureStorage {}

class _MemorySecureStorage implements SecureStorage {
  String? token;
  int deleteCount = 0;

  @override
  Future<String?> getToken() async => token;

  @override
  Future<void> saveToken(String token) async {
    this.token = token;
  }

  @override
  Future<void> deleteToken() async {
    deleteCount++;
    token = null;
  }
}

class _FakeAuthRepository implements AuthRepository {
  bool logoutCalled = false;

  @override
  Future<String> login(String email, String password) async =>
      'new-access-token';

  @override
  Future<void> logout() async {
    logoutCalled = true;
  }
}

void main() {
  group('AuthRepository', () {
    test('maps the API accessToken field from login', () async {
      final dio = Dio();
      dio.interceptors.add(
        InterceptorsWrapper(
          onRequest: (options, handler) {
            expect(options.path, '/auth/login');
            expect(options.data, {
              'email': 'analyst@example.test',
              'password': 'password123',
            });
            handler.resolve(
              Response(
                requestOptions: options,
                statusCode: 200,
                data: {'accessToken': 'api-access-token'},
              ),
            );
          },
        ),
      );

      expect(
        await AuthRepository(dio).login('analyst@example.test', 'password123'),
        'api-access-token',
      );
    });

    test('rejects login responses without the API accessToken field', () async {
      final dio = Dio();
      dio.interceptors.add(
        InterceptorsWrapper(
          onRequest: (options, handler) {
            handler.resolve(
              Response(
                requestOptions: options,
                statusCode: 200,
                data: {'token': 'incorrect-contract-token'},
              ),
            );
          },
        ),
      );

      await expectLater(
        AuthRepository(dio).login('analyst@example.test', 'password123'),
        throwsA(isA<FormatException>()),
      );
    });

    test('logout requests server-side session revocation', () async {
      final dio = Dio();
      dio.interceptors.add(
        InterceptorsWrapper(
          onRequest: (options, handler) {
            expect(options.path, '/auth/logout');
            handler.resolve(Response(requestOptions: options, statusCode: 200));
          },
        ),
      );

      await AuthRepository(dio).logout();
    });
  });

  test(
    'SecureStorage delegates token writes, reads, and removal to encrypted storage',
    () async {
      final storage = _MockFlutterSecureStorage();
      when(
        () => storage.write(key: 'auth_token', value: 'access-token'),
      ).thenAnswer((_) async {});
      when(
        () => storage.read(key: 'auth_token'),
      ).thenAnswer((_) async => 'access-token');
      when(() => storage.delete(key: 'auth_token')).thenAnswer((_) async {});
      final secureStorage = SecureStorage(storage);

      await secureStorage.saveToken('access-token');
      expect(await secureStorage.getToken(), 'access-token');
      await secureStorage.deleteToken();

      verify(
        () => storage.write(key: 'auth_token', value: 'access-token'),
      ).called(1);
      verify(() => storage.read(key: 'auth_token')).called(1);
      verify(() => storage.delete(key: 'auth_token')).called(1);
    },
  );

  test('API requests attach the securely restored access token', () async {
    final storage = _MemorySecureStorage()..token = 'stored-access-token';
    final container = ProviderContainer(
      overrides: [secureStorageProvider.overrideWithValue(storage)],
    );
    addTearDown(container.dispose);
    final dio = container.read(dioProvider);
    dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          expect(
            options.headers['Authorization'],
            'Bearer stored-access-token',
          );
          handler.resolve(Response(requestOptions: options, statusCode: 200));
        },
      ),
    );

    await dio.get<void>('/protected');
  });

  test(
    'auth state restores from secure storage and logout revokes then removes the token',
    () async {
      final storage = _MemorySecureStorage()..token = 'restored-access-token';
      final repository = _FakeAuthRepository();
      final container = ProviderContainer(
        overrides: [
          secureStorageProvider.overrideWithValue(storage),
          authRepositoryProvider.overrideWithValue(repository),
        ],
      );
      addTearDown(container.dispose);

      expect(container.read(authNotifierProvider).isLoading, isTrue);
      await Future<void>.delayed(Duration.zero);
      expect(container.read(authNotifierProvider).isAuthenticated, isTrue);

      await container
          .read(authNotifierProvider.notifier)
          .login('analyst@example.test', 'password123');
      expect(storage.token, 'new-access-token');
      expect(container.read(authNotifierProvider).isAuthenticated, isTrue);

      await container.read(authNotifierProvider.notifier).logout();
      expect(repository.logoutCalled, isTrue);
      expect(storage.token, isNull);
      expect(storage.deleteCount, 1);
      expect(container.read(authNotifierProvider).isAuthenticated, isFalse);
    },
  );
}
