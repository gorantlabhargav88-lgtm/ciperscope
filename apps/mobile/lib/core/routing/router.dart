
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mobile/features/auth/presentation/login_screen.dart';
import 'package:mobile/features/dashboard/presentation/dashboard_screen.dart';
import 'package:mobile/features/auth/providers/auth_provider.dart';
import 'package:mobile/features/investigations/presentation/investigation_detail_screen.dart';

final routerProvider = Provider<GoRouter>((ref) {
  final authState = ref.watch(authNotifierProvider);

  return GoRouter(
    initialLocation: '/',
    redirect: (context, state) {
      final isLoggingIn = state.uri.toString() == '/login';
      final isAuthenticated = authState.isAuthenticated;

      if (!isAuthenticated && !isLoggingIn) {
        return '/login';
      }
      if (isAuthenticated && isLoggingIn) {
        return '/';
      }
      return null;
    },
    routes: [
      GoRoute(
        path: '/login',
        builder: (context, state) => const LoginScreen(),
      ),
      GoRoute(
        path: '/',
        builder: (context, state) => const DashboardScreen(),
        routes: [
          GoRoute(
            path: 'investigations/:id',
            builder: (context, state) {
              final id = state.pathParameters['id']!;
              return InvestigationDetailScreen(investigationId: id);
            },
          ),
        ],
      ),
    ],
  );
});
