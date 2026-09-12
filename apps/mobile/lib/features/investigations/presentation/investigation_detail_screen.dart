import 'package:flutter/material.dart';
import 'package:mobile/core/theme/theme.dart';

class InvestigationDetailScreen extends StatelessWidget {
  final String investigationId;

  const InvestigationDetailScreen({super.key, required this.investigationId});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: Text('Investigation $investigationId'),
          bottom: const TabBar(
            tabs: [
              Tab(text: 'Overview'),
              Tab(text: 'Email Analysis'),
              Tab(text: 'Evidence'),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            _OverviewTab(),
            _EmailAnalysisTab(),
            _EvidenceTab(),
          ],
        ),
      ),
    );
  }
}

class _OverviewTab extends StatelessWidget {
  const _OverviewTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text('Overview Placeholder - Demo Data Only', style: TextStyle(color: AppTheme.textMuted)),
    );
  }
}

class _EmailAnalysisTab extends StatelessWidget {
  const _EmailAnalysisTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text('Email Analysis Foundation - Awaiting Phase 7', style: TextStyle(color: AppTheme.textMuted)),
    );
  }
}

class _EvidenceTab extends StatelessWidget {
  const _EvidenceTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text('Evidence Tracking Foundation - Awaiting Blockchain Integration', style: TextStyle(color: AppTheme.textMuted)),
    );
  }
}
