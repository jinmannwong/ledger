#include "dkg/dkg_messages.hpp"
#include "core/serializers/byte_array_buffer.hpp"
#include "core/serializers/counter.hpp"
#include "gtest/gtest.h"

using namespace fetch;
using namespace fetch::dkg;
using namespace fetch::crypto::bls;

TEST(dkg_messages, coefficients) {
    std::vector<DKGMessage::Coefficient> coefficients;
    Coefficients coeff{1, coefficients, "signature"};

    fetch::serializers::ByteArrayBuffer serialiser {coeff.serialize()};

    fetch::serializers::ByteArrayBuffer serialiser1(serialiser.data());
    Coefficients coeff1{serialiser1};

    for (auto ii = 0; ii < coeff.getCoefficients().size(); ++ii) {
        EXPECT_EQ(PublicKeyIsEqual(coeff1.getCoefficients()[ii], coeff.getCoefficients()[ii]), true);
    }
    EXPECT_EQ(coeff1.getPhase(), coeff.getPhase());
    EXPECT_EQ(coeff1.getSignature(), coeff.getSignature());
}

TEST(dkg_messages, shares) {
    std::unordered_map<DKGMessage::CabinetId, std::pair<DKGMessage::Share, DKGMessage::Share>> shares;
    Shares shareMessage{1, shares, "signature"};

    fetch::serializers::ByteArrayBuffer serialiser {shareMessage.serialize()};

    fetch::serializers::ByteArrayBuffer serialiser1(serialiser.data());
    Shares shareMessage1{serialiser1};

    for (const auto &i_share : shareMessage.getShares()) {
        EXPECT_EQ(shareMessage1.getShares().find(i_share.first) != shareMessage1.getShares().end(), true);
        EXPECT_EQ(blsSecretKeyIsEqual(&i_share.second.first, &shareMessage1.getShares().at(i_share.first).first), true);
    }
    EXPECT_EQ(shareMessage1.getPhase(), shareMessage.getPhase());
    EXPECT_EQ(shareMessage1.getSignature(), shareMessage.getSignature());
}

TEST(dkg_messages, complaints) {
    std::unordered_set<DKGMessage::CabinetId> complaints;
    Complaints complaintMsg{complaints, "signature"};

    fetch::serializers::ByteArrayBuffer serialiser {complaintMsg.serialize()};

    fetch::serializers::ByteArrayBuffer serialiser1(serialiser.data());
    Complaints complaintMsg1{serialiser1};

    EXPECT_EQ(complaintMsg1.getComplaints(), complaintMsg.getComplaints());
    EXPECT_EQ(complaintMsg1.getSignature(), complaintMsg.getSignature());
}

TEST(dkg_messages, envelope) {
    std::unordered_set<DKGMessage::CabinetId> complaints;
    Complaints complaintMsg{complaints, "signature"};

    // Put into DKGEnvelop
    DKGEnvelop env{complaintMsg};

    // Serialise the envelop
    fetch::serializers::SizeCounter<fetch::serializers::ByteArrayBuffer> env_counter;
    env_counter << env;

    fetch::serializers::ByteArrayBuffer env_serialiser;
    env_serialiser.Reserve(env_counter.size());
    env_serialiser << env;

    fetch::serializers::ByteArrayBuffer env_serialiser1{env_serialiser.data()};
    DKGEnvelop env1;
    env_serialiser1 >> env1;

    // Check the message type of envelops match
    EXPECT_EQ(env1.getMessage()->getType(), DKGMessage::MessageType::COMPLAINT);
    EXPECT_EQ(env1.getMessage()->getSignature(), complaintMsg.getSignature());
    EXPECT_EQ(std::dynamic_pointer_cast<Complaints>(env1.getMessage()) -> getComplaints(), complaintMsg.getComplaints());
}