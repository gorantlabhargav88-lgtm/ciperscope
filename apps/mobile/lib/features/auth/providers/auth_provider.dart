import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/core/security/secure_storage.dart';
import 'package:mobile/features/auth/data/auth_repository.dart';

class AuthState {
  final bool isAuthenticated;
  final bool isLoading;
  final String? error;

  AuthState({this.isAuthenticated = false, this.isLoading = false, this.error});

  AuthState copyWith({bool? isAuthenticated, bool? isLoading, String? error}) {
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
    _restoreSession();
    return AuthState(isLoading: true);
  }

  Future<void> _restoreSession() async {
    try {
      final token = await _storage.getToken();
      state = AuthState(isAuthenticated: token != null);
    } catch (error) {
      state = AuthState(error: error.toString());
    }
  }

  Future<void> login(String email, String password) async {
    state = AuthState(isAuthenticated: state.isAuthenticated, isLoading: true);
    try {
      final token = await _repository.login(email, password);
      await _storage.saveToken(token);
      state = AuthState(isAuthenticated: true);
    } catch (e) {
      state = AuthState(
        isAuthenticated: state.isAuthenticated,
        error: e.toString(),
      );
    }
  }

  Future<void> logout() async {
    state = AuthState(isAuthenticated: state.isAuthenticated, isLoading: true);
    String? error;
    try {
      await _repository.logout();
    } catch (exception) {
      error = exception.toString();
    }

    try {
      await _storage.deleteToken();
      state = AuthState(error: error);
    } catch (exception) {
      state = AuthState(isAuthenticated: true, error: exception.toString());
    }
  }
}
