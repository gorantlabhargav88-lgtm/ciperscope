import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mobile/core/theme/theme.dart';
import 'package:mobile/features/auth/providers/auth_provider.dart';

class DashboardScreen extends ConsumerWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Dashboard'),
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            onPressed: () {
              ref.read(authNotifierProvider.notifier).logout();
            },
          )
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: AppTheme.highAmber.withValues(alpha: 0.1),
                border: Border.all(color: AppTheme.highAmber),
                borderRadius: BorderRadius.circular(4),
              ),
              child: const Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.warning_amber_rounded, color: AppTheme.highAmber, size: 20),
                  SizedBox(width: 8),
                  Text(
                    'DEMO MODE',
                    style: TextStyle(
                      color: AppTheme.highAmber,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Active Investigations',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 16),
            Card(
              child: ListTile(
                leading: const CircleAvatar(
                  backgroundColor: AppTheme.criticalRed,
                  child: Icon(Icons.security, color: Colors.white),
                ),
                title: const Text('Suspicious Wire Transfer Request'),
                subtitle: const Text('INV-2023-001 • Critical'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  context.go('/investigations/INV-2023-001');
                },
              ),
            ),
            Card(
              child: ListTile(
                leading: const CircleAvatar(
                  backgroundColor: AppTheme.highAmber,
                  child: Icon(Icons.email, color: Colors.white),
                ),
                title: const Text('Phishing Campaign: IT Support'),
                subtitle: const Text('INV-2023-002 • High'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  context.go('/investigations/INV-2023-002');
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}
