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
      final response = await _dio.post('/auth/login', data: {
        'email': email,
        'password': password,
      });
      return response.data['token']; // Adjust based on your Fastify API response
    } on DioException catch (e) {
      throw Exception(e.response?.data['message'] ?? 'Failed to login');
    }
  }
}
