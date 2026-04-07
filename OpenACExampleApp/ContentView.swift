//
//  ContentView.swift
//  OpenACExampleApp
//
//  Created by 鄭雅文 on 2026/4/5.
//

import SwiftUI

struct ContentView: View {
    @State private var vm = ProofViewModel()

    var body: some View {
        NavigationStack {
            List {
                // ── Circuit Download ───────────────────────────────────
                if !vm.circuitReady || vm.downloadSeconds != nil {
                    Section {
                        CircuitDownloadCard(vm: vm)
                    } header: {
                        Text("Setup")
                    }
                }

                // ── Pipeline Steps ─────────────────────────────────────
                Section {
                    StepRow(index: 1, title: "Setup Keys",
                            subtitle: "Generate proving & verifying keys",
                            status: vm.setupStatus)
                    StepRow(index: 2, title: "Generate Proof",
                            subtitle: "Prove the RS256 circuit",
                            status: vm.proveStatus)
                    StepRow(index: 3, title: "Verify",
                            subtitle: "Check the proof is valid",
                            status: vm.verifyStatus)
                } header: {
                    Text("Pipeline")
                }
            }
            .navigationTitle("OpenAC ZK Proof")
            .toolbar {
                ToolbarItem(placement: .bottomBar) {
                    Button {
                        Task { await vm.runAll() }
                    } label: {
                        Label("Run All Steps", systemImage: "play.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(vm.isRunning || !vm.circuitReady)
                }
            }
        }
        .task {
            try? vm.prepareResources()
        }
    }
}

// MARK: - Circuit Download Card

private struct CircuitDownloadCard: View {
    var vm: ProofViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Circuit file required", systemImage: "arrow.down.circle.fill")
                .font(.headline)
                .foregroundStyle(.blue)

            Text("rs256.r1cs (~749 MB) must be downloaded before running the pipeline.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            if vm.isDownloading {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: vm.downloadProgress)
                    Text(vm.downloadProgress < 1
                         ? "\(Int(vm.downloadProgress * 100))% downloaded"
                         : "Extracting…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                Button {
                    Task { await vm.downloadCircuit() }
                } label: {
                    Label("Download Circuit", systemImage: "icloud.and.arrow.down")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.regular)
            }

            if vm.downloadSeconds != nil || vm.unzipSeconds != nil {
                VStack(alignment: .leading, spacing: 2) {
                    if let s = vm.downloadSeconds {
                        Label("Downloaded in \(s, specifier: "%.1f") s", systemImage: "arrow.down.circle")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    if let s = vm.unzipSeconds {
                        Label("Extracted in \(s, specifier: "%.1f") s", systemImage: "archivebox")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if let err = vm.downloadError {
                Label(err, systemImage: "xmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Step Row

private struct StepRow: View {
    let index: Int
    let title: String
    let subtitle: String
    let status: ProofViewModel.StepStatus

    var body: some View {
        HStack(spacing: 16) {
            IndexBadge(index: index, status: status)

            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)

                if case .success(let detail) = status {
                    Text(detail)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.green)
                        .padding(.top, 2)
                }
                if case .failure(let msg) = status {
                    Text(msg)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .padding(.top, 2)
                }
            }

            Spacer()

            if case .running = status {
                ProgressView().controlSize(.small)
            }
        }
        .padding(.vertical, 4)
        .animation(.default, value: status)
    }
}

// MARK: - Index Badge

private struct IndexBadge: View {
    let index: Int
    let status: ProofViewModel.StepStatus

    private var color: Color {
        switch status {
        case .idle, .running: return .secondary
        case .success:        return .green
        case .failure:        return .red
        }
    }

    private var symbol: String {
        switch status {
        case .idle, .running: return "\(index).circle"
        case .success:        return "checkmark.circle.fill"
        case .failure:        return "xmark.circle.fill"
        }
    }

    var body: some View {
        Image(systemName: symbol)
            .font(.title2)
            .foregroundStyle(color)
            .frame(width: 32)
    }
}

#Preview {
    ContentView()
}
