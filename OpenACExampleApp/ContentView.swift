//
//  ContentView.swift
//  OpenACExampleApp
//
//  Created by 鄭雅文 on 2026/4/5.
//

import SwiftUI

struct ContentView: View {
    @Bindable var vm: ProofViewModel

    private var spTicketSymbol: String {
        switch vm.spTicketStatus {
        case .idle, .running: return "ticket"
        case .success:        return "checkmark.circle.fill"
        case .failure:        return "xmark.circle.fill"
        }
    }

    private var athResultSymbol: String {
        switch vm.athResultStatus {
        case .idle, .running: return "checkmark.shield"
        case .success:        return "checkmark.shield.fill"
        case .failure:        return "xmark.shield.fill"
        }
    }

    private func spTicketColor(_ status: ProofViewModel.StepStatus) -> Color {
        switch status {
        case .idle, .running: return .secondary
        case .success:        return .green
        case .failure:        return .red
        }
    }

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

                // ── SP Ticket / MOICA ─────────────────────────────────
                Section {
                    // Row 0 – ID number input
                    HStack {
                        Text("ID Number")
                            .font(.subheadline)
                        SecureField("e.g. A123456789", text: $vm.idNum)
                            .textFieldStyle(.roundedBorder)
                    }

                    // Row 1 – fetch ticket
                    HStack(spacing: 16) {
                        Image(systemName: spTicketSymbol)
                            .font(.title2)
                            .foregroundStyle(spTicketColor(vm.spTicketStatus))
                            .frame(width: 32)

                        VStack(alignment: .leading, spacing: 2) {
                            Text("Get SP Ticket").font(.headline)
                            Text("POST /fido/sp-ticket").font(.caption).foregroundStyle(.secondary)

                            if case .success(let detail) = vm.spTicketStatus {
                                Text(detail)
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(.green)
                                    .padding(.top, 2)
                                if let ticket = vm.spTicket {
                                    Text(ticket)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                        .lineLimit(3)
                                        .truncationMode(.middle)
                                        .textSelection(.enabled)
                                        .padding(.top, 1)
                                }
                            }
                            if case .failure(let msg) = vm.spTicketStatus {
                                Text(msg)
                                    .font(.caption)
                                    .foregroundStyle(.red)
                                    .padding(.top, 2)
                            }
                        }

                        Spacer()

                        if case .running = vm.spTicketStatus {
                            ProgressView().controlSize(.small)
                        } else {
                            Button {
                                Task { await vm.computeSPTicket() }
                            } label: {
                                Image(systemName: "arrow.down.circle")
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                    }
                    .padding(.vertical, 4)
                    .animation(.default, value: vm.spTicketStatus)

                    // Row 2 – open MOICA (visible once ticket is ready)
                    if vm.spTicket != nil {
                        HStack(spacing: 16) {
                            Image(systemName: "person.badge.key.fill")
                                .font(.title2)
                                .foregroundStyle(.blue)
                                .frame(width: 32)

                            VStack(alignment: .leading, spacing: 2) {
                                Text("Verify with MOICA").font(.headline)
                                Text("Opens mobilemoica:// · returns to openac://callback")
                                    .font(.caption).foregroundStyle(.secondary)

                                if let val = vm.rtnVal {
                                    Text("rtn_val: \(val)")
                                        .font(.caption.monospacedDigit())
                                        .foregroundStyle(.green)
                                        .padding(.top, 2)
                                }
                            }

                            Spacer()

                            Button {
                                vm.openMOICA()
                            } label: {
                                Image(systemName: "arrow.up.forward.app")
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                        }
                        .padding(.vertical, 4)
                    }

                    // Row 3 – ath-result
                    if vm.spTicket != nil {
                        HStack(spacing: 16) {
                            Image(systemName: athResultSymbol)
                                .font(.title2)
                                .foregroundStyle(spTicketColor(vm.athResultStatus))
                                .frame(width: 32)

                            VStack(alignment: .leading, spacing: 2) {
                                Text("Auth Result").font(.headline)
                                Text("POST /fido/ath-result").font(.caption).foregroundStyle(.secondary)

                                if case .success(let detail) = vm.athResultStatus {
                                    Text(detail)
                                        .font(.caption.monospacedDigit())
                                        .foregroundStyle(.green)
                                        .padding(.top, 2)
                                }
                                if case .failure(let msg) = vm.athResultStatus {
                                    Text(msg)
                                        .font(.caption)
                                        .foregroundStyle(.red)
                                        .padding(.top, 2)
                                }
                            }

                            Spacer()

                            if case .running = vm.athResultStatus {
                                ProgressView().controlSize(.small)
                            } else {
                                Button {
                                    Task { await vm.pollAthResult() }
                                } label: {
                                    Image(systemName: "checkmark.shield")
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                        }
                        .padding(.vertical, 4)
                        .animation(.default, value: vm.athResultStatus)
                    }

                    // Row 4 – generate input.json
                    HStack(spacing: 16) {
                        Image(systemName: {
                            switch vm.generateInputStatus {
                            case .idle, .running: return "doc.badge.gearshape"
                            case .success:        return "checkmark.circle.fill"
                            case .failure:        return "xmark.circle.fill"
                            }
                        }())
                        .font(.title2)
                        .foregroundStyle(spTicketColor(vm.generateInputStatus))
                        .frame(width: 32)

                        VStack(alignment: .leading, spacing: 2) {
                            Text("Generate Input").font(.headline)
                            Text("Build circuit input from MOICA response").font(.caption).foregroundStyle(.secondary)

                            if case .success(let detail) = vm.generateInputStatus {
                                Text(detail)
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(.green)
                                    .lineLimit(2)
                                    .truncationMode(.middle)
                                    .padding(.top, 2)
                            }
                            if case .failure(let msg) = vm.generateInputStatus {
                                Text(msg)
                                    .font(.caption)
                                    .foregroundStyle(.red)
                                    .padding(.top, 2)
                            }
                        }

                        Spacer()

                        if case .running = vm.generateInputStatus {
                            ProgressView().controlSize(.small)
                        } else {
                            Button {
                                Task { await vm.runGenerateInput() }
                            } label: {
                                Image(systemName: "arrow.trianglehead.2.clockwise")
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                    }
                    .padding(.vertical, 4)
                    .animation(.default, value: vm.generateInputStatus)
                } header: {
                    Text("FIDO / MOICA")
                }

                // ── Pipeline Steps ─────────────────────────────────────
                Section {
                    StepRow(index: 1, title: "Setup Keys",
                            subtitle: "Generate proving & verifying keys",
                            status: vm.setupStatus)
                    StepRow(index: 2, title: "Generate Proof",
                            subtitle: "Prove the sha256rsa4096 circuit",
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

            Text("sha256rsa4096.r1cs (~97.43 MB) must be downloaded before running the pipeline.")
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
    ContentView(vm: ProofViewModel())
}
