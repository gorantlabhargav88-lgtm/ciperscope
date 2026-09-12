import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/core/security/secure_storage.dart';
import 'package:mobile/features/auth/data/auth_repository.dart';

class AuthState {
  final bool isAuthenticated;
  final bool isLoading;
  final String? error;

  AuthState({
    this.isAuthenticated = false,
    this.isLoading = false,
    this.error,
  });

  AuthState copyWith({
    bool? isAuthenticated,
    bool? isLoading,
    String? error,
  }) {
    return AuthState(
      isAuthenticated: isAuthenticated ?? this.isAuthenticated,
      isLoading: isLoading ?? this.isLoading,
      error: error ?? this.error,
    );
  }
}

final authNotifierProvider = NotifierProvider<AuthNotifier, AuthState>(() {
  return AuthNotifier();
});

class AuthNotifier extends Notifier<AuthState> {
  late final AuthRepository _repository;
  late final SecureStorage _storage;

  @override
  AuthState build() {
    _repository = ref.watch(authRepositoryProvider);
    _storage = ref.watch(secureStorageProvider);
    _checkAuthStatus();
    return AuthState();
  }

  Future<void> _checkAuthStatus() async {
    final token = await _storage.getToken();
    if (token != null) {
      state = state.copyWith(isAuthenticated: true);
    }
  }

  Future<void> login(String email, String password) async {
    state = state.copyWith(isLoading: true, error: null);
    try {
      final token = await _repository.login(email, password);
      await _storage.saveToken(token);
      state = state.copyWith(isLoading: false, isAuthenticated: true);
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }

  Future<void> logout() async {
    await _storage.deleteToken();
    state = state.copyWith(isAuthenticated: false);
  }
}
