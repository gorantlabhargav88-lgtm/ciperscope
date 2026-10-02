import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/core/security/secure_storage.dart';
import 'package:mobile/main.dart';
import 'package:mobile/features/auth/presentation/login_screen.dart';
import 'package:mobile/features/dashboard/presentation/dashboard_screen.dart';

class _FakeSecureStorage implements SecureStorage {
  _FakeSecureStorage(this.token);

  final String? token;

  @override
  Future<String?> getToken() async => token;

  @override
  Future<void> saveToken(String token) async {}

  @override
  Future<void> deleteToken() async {}
}

void main() {
  testWidgets('App boots and shows Login Screen', (WidgetTester tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(_FakeSecureStorage(null)),
        ],
        child: const CiperScopeApp(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(LoginScreen), findsOneWidget);
    expect(find.text('SOC Command Center'), findsOneWidget);
  });

  testWidgets('App restores an existing session from secure storage', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(
            _FakeSecureStorage('stored-access-token'),
          ),
        ],
        child: const CiperScopeApp(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(DashboardScreen), findsOneWidget);
  });
}
