import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/core/networking/api_client.dart';

final authRepositoryProvider = Provider<AuthRepository>((ref) {
  return AuthRepository(ref.watch(dioProvider));
});

class AuthRepository {
  final Dio _dio;

  AuthRepository(this._dio);

  Future<String> login(String email, String password) async {
    try {
      final response = await _dio.post(
        '/auth/login',
        data: {'email': email, 'password': password},
      );
      final data = response.data;
      if (data is! Map<String, dynamic> ||
          data['accessToken'] is! String ||
          (data['accessToken'] as String).isEmpty) {
        throw const FormatException(
          'Login response did not contain an access token',
        );
      }
      return data['accessToken'] as String;
    } on DioException catch (e) {
      final responseData = e.response?.data;
      final message = responseData is Map ? responseData['message'] : null;
      throw Exception(message ?? 'Failed to login');
    }
  }

  Future<void> logout() async {
    await _dio.post<void>('/auth/logout');
  }
}
