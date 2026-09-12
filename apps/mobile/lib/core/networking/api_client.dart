import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/core/security/secure_storage.dart';

final dioProvider = Provider<Dio>((ref) {
  final secureStorage = ref.watch(secureStorageProvider);
  final dio = Dio(
    BaseOptions(
      // Ensure backend runs on 10.0.2.2 for Android Emulator testing
      baseUrl: const String.fromEnvironment('API_URL', defaultValue: 'http://10.0.2.2:3000/api/v1'),
      connectTimeout: const Duration(seconds: 10),
      receiveTimeout: const Duration(seconds: 10),
    ),
  );

  dio.interceptors.add(
    InterceptorsWrapper(
      onRequest: (options, handler) async {
        final token = await secureStorage.getToken();
        if (token != null) {
          options.headers['Authorization'] = 'Bearer $token';
        }
        return handler.next(options);
      },
      onError: (DioException error, handler) async {
        // Simple error handling, could handle 401 token refresh here
        return handler.next(error);
      },
    ),
  );

  return dio;
});
