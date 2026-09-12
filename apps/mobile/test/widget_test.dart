import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/main.dart';
import 'package:mobile/features/auth/presentation/login_screen.dart';

void main() {
  testWidgets('App boots and shows Login Screen', (WidgetTester tester) async {
    await tester.pumpWidget(const ProviderScope(child: CiperScopeApp()));
    await tester.pumpAndSettle();
    
    expect(find.byType(LoginScreen), findsOneWidget);
    expect(find.text('SOC Command Center'), findsOneWidget);
  });
}
