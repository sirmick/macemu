# libdatachannel Signaling Research & Simplification Guide

## Executive Summary

**Key Finding**: libdatachannel provides **excellent WebRTC primitives** but **no signaling server helpers**. However, the example patterns are so simple and effective that adopting them will reduce our signaling code from **385 lines to ~130 lines** (65% reduction).

## 1. What libdatachannel Provides

✅ **Provides**:
- WebRTC PeerConnection implementation
- Data Channels
- Media tracks (RTP/RTCP handling)
- WebSocket **client** implementation
- Basic WebSocket **server** (`rtc::WebSocketServer`)
- Automatic ICE candidate queuing
- Built-in gathering state management

❌ **Does NOT Provide**:
- Signaling server logic
- Message routing/relay
- Peer management utilities
- HTTP routing

## 2. Current Implementation Analysis

### Current Code (server.cpp lines 1861-2087)
- **Total Lines**: 385 lines
  - Signaling protocol: 227 lines
  - Peer creation: 158 lines
- **Complexity**: High
  - Custom "connect" message type
  - Manual gathering state management
  - Pending candidate queue
  - Complex state tracking

### Issues Found
1. **Manual gathering state management** (~60 lines) - unnecessary!
2. **Pending candidate queue** (~30 lines) - libdatachannel does this!
3. **Custom JSON parsing** (~40 lines) - we have nlohmann/json!
4. **Complex message routing** - could be much simpler

## 3. libdatachannel Example Patterns

### Best Examples to Study

| Example | Location | Key Lesson |
|---------|----------|------------|
| **Streamer** | `libdatachannel/examples/streamer/main.cpp` | Server-side media tracks |
| **Client** | `libdatachannel/examples/client/main.cpp` | Clean callback usage |
| **Helpers** | `libdatachannel/examples/streamer/helpers.hpp` | State management |
| **Signaling (Node.js)** | `libdatachannel/examples/signaling-server-nodejs/` | Simple relay pattern |
| **Signaling (Qt C++)** | `libdatachannel/examples/signaling-server-qt/` | C++ relay pattern |

### Pattern 1: Auto-send with Callbacks

**Current approach** (manual, 60+ lines):
```cpp
peer->pc->onGatheringStateChange([ws, peer_id](rtc::PeerConnection::GatheringState state) {
    if (state == rtc::PeerConnection::GatheringState::Complete) {
        auto description = pc->localDescription();
        std::string sdp = std::string(description.value());
        // Build JSON manually...
        std::string json = "{\"type\":\"offer\",\"sdp\":\"" + escape(sdp) + "\"}";
        ws->send(json);
    }
});
```

**libdatachannel pattern** (~10 lines):
```cpp
#include <nlohmann/json.hpp>
using json = nlohmann::json;

peer->pc->onLocalDescription([ws, peer_id](rtc::Description desc) {
    json msg = {
        {"type", desc.typeString()},  // "offer" or "answer"
        {"sdp", std::string(desc)}
    };
    ws->send(msg.dump());
});

peer->pc->onLocalCandidate([ws, peer_id](rtc::Candidate cand) {
    json msg = {
        {"type", "candidate"},
        {"candidate", std::string(cand)},
        {"mid", cand.mid()}
    };
    ws->send(msg.dump());
});
```

**Benefits**:
- ✅ Automatic trickle ICE (candidates sent as generated)
- ✅ No manual state management
- ✅ Clean JSON with nlohmann library
- ✅ Works for both offers and answers

### Pattern 2: No Pending Candidate Queue Needed

**Current approach** (~30 lines):
```cpp
struct PeerConnection {
    std::vector<std::pair<std::string, std::string>> pending_candidates;
    // ...
};

// On receiving candidate before answer
pending_candidates.push_back({candidate, mid});

// Later, in answer handler:
if (!peer->pending_candidates.empty()) {
    for (const auto& [candidate, mid] : peer->pending_candidates) {
        peer->pc->addRemoteCandidate(rtc::Candidate(candidate, mid));
    }
    peer->pending_candidates.clear();
}
```

**libdatachannel pattern** (~1 line):
```cpp
// Just add immediately - libdatachannel queues internally if remote description not set yet
peer->pc->addRemoteCandidate(rtc::Candidate(candidate, mid));
```

**Why it works**: libdatachannel's `PeerConnection` class already has internal queuing for candidates received before remote description is set.

### Pattern 3: Simple Message Handling

**Current approach** (3 message types, 60+ lines):
```cpp
void process_signaling(std::shared_ptr<rtc::WebSocket> ws, const std::string& msg) {
    std::string type = json_get_string(msg, "type");  // Manual parsing

    if (type == "connect") {
        // 60 lines: create peer, setup tracks, gather candidates...
    } else if (type == "answer") {
        // 30 lines: find peer, add to pending queue, set remote description...
    } else if (type == "candidate") {
        // 20 lines: find peer, add to pending queue...
    }
}
```

**libdatachannel pattern** (2 message types, ~20 lines):
```cpp
void process_signaling(std::shared_ptr<rtc::WebSocket> ws, const std::string& msg) {
    using json = nlohmann::json;
    json message = json::parse(msg);
    std::string type = message["type"];

    // Find peer for this WebSocket
    auto peer = findPeer(ws);
    if (!peer) return;

    if (type == "answer") {
        std::string sdp = message["sdp"];
        peer->pc->setRemoteDescription(rtc::Description(sdp, "answer"));
    } else if (type == "candidate") {
        std::string candidate = message["candidate"];
        std::string mid = message["mid"];
        peer->pc->addRemoteCandidate(rtc::Candidate(candidate, mid));
    }
}
```

**Why simpler**:
- No "connect" message - peer created when WebSocket connects
- No pending queue management
- No manual JSON parsing

### Pattern 4: State Management

**From `examples/streamer/helpers.hpp`**:
```cpp
struct Client {
    enum class State {
        Waiting,
        WaitingForVideo,
        WaitingForAudio,
        Ready
    };

    std::shared_ptr<rtc::PeerConnection> peerConnection;
    std::optional<std::shared_ptr<ClientTrackData>> video;
    std::optional<std::shared_ptr<ClientTrackData>> audio;
    std::optional<std::shared_ptr<rtc::DataChannel>> dataChannel;

    void setState(State state);
    State getState();

private:
    std::shared_mutex _mutex;
    State state = State::Waiting;
};

struct ClientTrackData {
    std::shared_ptr<rtc::Track> track;
    std::shared_ptr<rtc::RtcpSrReporter> sender;
};
```

**Recommendation**: Adopt similar state machine for our `PeerConnection` struct.

## 4. Simplified Peer Creation

**From `examples/streamer/main.cpp` (line 252)**:

```cpp
shared_ptr<Client> createPeer(const Configuration &config,
                               weak_ptr<WebSocket> wws,
                               string id) {
    auto pc = make_shared<PeerConnection>(config);
    auto client = make_shared<Client>(pc, id);

    // State callbacks
    pc->onStateChange([id](PeerConnection::State state) {
        cout << "Peer " << id << " state: " << state << endl;
    });

    pc->onGatheringStateChange([id](PeerConnection::GatheringState state) {
        cout << "Peer " << id << " gathering: " << state << endl;
    });

    // Signaling callbacks (auto-send offer + candidates)
    pc->onLocalDescription([wws, id](Description desc) {
        if (auto ws = wws.lock()) {
            json msg = {{"type", desc.typeString()}, {"sdp", string(desc)}};
            ws->send(msg.dump());
        }
    });

    pc->onLocalCandidate([wws, id](Candidate cand) {
        if (auto ws = wws.lock()) {
            json msg = {{"type", "candidate"},
                       {"candidate", string(cand)},
                       {"mid", cand.mid()}};
            ws->send(msg.dump());
        }
    });

    // Setup tracks
    auto video = addVideo(client, config.video_codec);
    auto audio = addAudio(client, config.audio_codec);

    // Start offer generation
    pc->setLocalDescription();

    return client;
}
```

**Key differences from our code**:
- Uses `weak_ptr` for WebSocket (prevents dangling references)
- Delegates to helper functions (`addVideo`, `addAudio`)
- Callbacks are set before `setLocalDescription()` (so they fire immediately)
- No manual gathering management

## 5. Recommended Changes

### High Priority (Immediate Benefits)

#### 5.1 Replace manual gathering with `onLocalDescription`
**Impact**: -60 lines, cleaner code

**Before**:
```cpp
peer->pc->onGatheringStateChange([ws, peer_id, wpc](rtc::PeerConnection::GatheringState state) {
    if (state == rtc::PeerConnection::GatheringState::Complete) {
        // Get local description
        // Build JSON manually
        // Send offer
    }
});
```

**After**:
```cpp
peer->pc->onLocalDescription([ws, peer_id](rtc::Description desc) {
    json msg = {{"type", desc.typeString()}, {"sdp", std::string(desc)}};
    ws->send(msg.dump());
});
```

#### 5.2 Remove pending candidate queue
**Impact**: -30 lines, trust libdatachannel

**Before**:
```cpp
struct PeerConnection {
    std::vector<std::pair<std::string, std::string>> pending_candidates;
};

// In handler:
if (remote_description_set) {
    pc->addRemoteCandidate(...);
} else {
    pending_candidates.push_back(...);
}
```

**After**:
```cpp
// Just add - libdatachannel handles queuing
pc->addRemoteCandidate(rtc::Candidate(candidate, mid));
```

#### 5.3 Use nlohmann/json directly
**Impact**: -40 lines, remove custom helpers

**Before**:
```cpp
std::string json_escape(const std::string& s) { /* ... */ }
std::string json_get_string(const std::string& json, const std::string& key) { /* ... */ }

std::string type = json_get_string(msg, "type");
```

**After**:
```cpp
#include <nlohmann/json.hpp>
using json = nlohmann::json;

json message = json::parse(msg);
std::string type = message["type"];
std::string sdp = message.value("sdp", "");  // with default
```

#### 5.4 Adopt weak_ptr pattern
**Impact**: Prevents dangling WebSocket references

**Before**:
```cpp
peer->pc->onLocalDescription([ws, peer_id](rtc::Description desc) {
    // What if ws is deleted?
    ws->send(...);
});
```

**After**:
```cpp
std::weak_ptr<rtc::WebSocket> weak_ws = ws;
peer->pc->onLocalDescription([weak_ws, peer_id](rtc::Description desc) {
    if (auto ws = weak_ws.lock()) {
        ws->send(...);
    }
});
```

### Medium Priority (For Refactoring)

#### 5.5 Simplify message handling
**Impact**: -40 lines

Remove custom "connect" message type. Create peer when WebSocket connects, not on first message.

#### 5.6 Extract signaling module
**Impact**: Better organization

Create `webrtc/signaling_server.cpp` with clean interface.

#### 5.7 Adopt Client state machine
**Impact**: Better peer lifecycle tracking

Use enum-based state management from helpers.hpp example.

## 6. Code Reduction Summary

| Component | Current | After | Reduction |
|-----------|---------|-------|-----------|
| **Peer creation** | 158 lines | ~80 lines | -49% |
| **Message handling** | 227 lines | ~50 lines | -78% |
| **JSON helpers** | 40 lines | 0 lines | -100% (use nlohmann) |
| **Total signaling** | **385 lines** | **~130 lines** | **-66%** |

## 7. Updated Refactoring Plan

### Phase 7 (WebRTC) - Revised Estimates

| Module | Old Estimate | New Estimate | Savings |
|--------|--------------|--------------|---------|
| signaling_server | 300 lines | **150 lines** | -50% |
| peer_manager | 250 lines | **200 lines** | -20% |
| track_factory | 200 lines | **180 lines** | -10% |
| frame_sender | 300 lines | 300 lines | 0% |
| input_handler | 200 lines | 200 lines | 0% |
| **Total** | **1,250 lines** | **1,030 lines** | **-18%** |

## 8. Implementation Checklist

### Immediate (Pre-refactor improvements)
- [ ] Add nlohmann/json include path to Makefile
- [ ] Replace `json_get_string()` with nlohmann/json
- [ ] Replace `json_escape()` with nlohmann/json
- [ ] Switch to `onLocalDescription` callback
- [ ] Remove pending candidate queue
- [ ] Add weak_ptr guards

### During Refactor
- [ ] Extract signaling_server module
- [ ] Extract peer_manager module
- [ ] Adopt Client state machine pattern
- [ ] Add ClientTrackData wrapper
- [ ] Create track helper functions

### Post-refactor
- [ ] Add unit tests for signaling
- [ ] Benchmark before/after
- [ ] Update documentation

## 9. Example Files to Study

### Must Read (in order)
1. **`libdatachannel/examples/client/main.cpp`** - Clean callback pattern
2. **`libdatachannel/examples/streamer/main.cpp`** - Server-side tracks
3. **`libdatachannel/examples/streamer/helpers.hpp`** - State management
4. **`libdatachannel/examples/signaling-server-qt/SignalingServer.cpp`** - C++ relay

### Reference
- **`libdatachannel/README.md`** - API overview
- **`libdatachannel/DOC.md`** - C API reference

## 10. FAQ

**Q: Why doesn't libdatachannel provide signaling helpers?**
A: Signaling is intentionally outside the WebRTC spec. The library provides the primitives (callbacks, state management) but apps define their own protocols.

**Q: Should we use rtc::WebSocketServer?**
A: No, it's too basic. Keep using the current HTTP server with WebSocket upgrades.

**Q: Do we need a separate signaling server process?**
A: No, our architecture (integrated server) is correct. The examples show this works well.

**Q: Will this improve performance?**
A: Slightly - trickle ICE means candidates sent immediately, faster connection establishment.

**Q: Is this a breaking change for the web client?**
A: No, we can keep the same message format. Only the server implementation changes.

## 11. Next Steps

1. **Review this document** with the refactoring plan
2. **Update REFACTOR_PLAN.md** with simplified estimates
3. **Start Phase 1** (utilities) with nlohmann/json integration
4. **Apply high-priority changes** before full refactor
5. **Use example patterns** as templates for new modules

---

**Key Takeaway**: libdatachannel's examples are the best documentation. Follow their patterns for clean, simple, robust signaling code.
