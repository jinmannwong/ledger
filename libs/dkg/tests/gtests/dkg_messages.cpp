#include "dkg/dkg_messages.hpp"
#include "core/serializers/byte_array_buffer.hpp"
#include "core/serializers/counter.hpp"
#include "gtest/gtest.h"


using namespace fetch;
using namespace fetch::dkg;

TEST(dkg_messages, coefficients) {
    std::vector<std::string> coefficients;
    coefficients.push_back("coeff1");
    CoefficientsMessage coeff{1, coefficients, "signature"};

    fetch::serializers::ByteArrayBuffer serialiser {coeff.Serialize()};

    fetch::serializers::ByteArrayBuffer serialiser1(serialiser.data());
    CoefficientsMessage coeff1{serialiser1};

    for (auto ii = 0; ii < coeff.Coefficients().size(); ++ii) {
        EXPECT_EQ(coeff1.Coefficients()[ii], coeff.Coefficients()[ii]);
    }
    EXPECT_EQ(coeff1.Phase(), coeff.Phase());
    EXPECT_EQ(coeff1.Signature(), coeff.Signature());
}

TEST(dkg_messages, shares) {
    std::unordered_map<DKGMessage::CabinetId, std::pair<std::string, std::string>> shares;
    shares.insert({"0", {"s_ij", "sprime_ij"}});

    SharesMessage shareMessage{1, shares, "signature"};

    fetch::serializers::ByteArrayBuffer serialiser {shareMessage.Serialize()};

    fetch::serializers::ByteArrayBuffer serialiser1(serialiser.data());
    SharesMessage shareMessage1{serialiser1};

    for (const auto &i_share : shareMessage.Shares()) {
        EXPECT_EQ(shareMessage1.Shares().find(i_share.first) != shareMessage1.Shares().end(), true);
        EXPECT_EQ(i_share.second.first, shareMessage1.Shares().at(i_share.first).first);
    }
    EXPECT_EQ(shareMessage1.Phase(), shareMessage.Phase());
    EXPECT_EQ(shareMessage1.Signature(), shareMessage.Signature());
}

TEST(dkg_messages, complaints) {
    std::unordered_set<DKGMessage::CabinetId> complaints;
    ComplaintsMessage complaintMsg{complaints, "signature"};

    fetch::serializers::ByteArrayBuffer serialiser {complaintMsg.Serialize()};

    fetch::serializers::ByteArrayBuffer serialiser1(serialiser.data());
    ComplaintsMessage complaintMsg1{serialiser1};

    EXPECT_EQ(complaintMsg1.Complaints(), complaintMsg.Complaints());
    EXPECT_EQ(complaintMsg1.Signature(), complaintMsg.Signature());
}

TEST(dkg_messages, envelope) {
    std::unordered_set<DKGMessage::CabinetId> complaints;
    ComplaintsMessage complaintMsg{complaints, "signature"};

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
    EXPECT_EQ(env1.Message()->Type(), DKGMessage::MessageType::COMPLAINT);
    EXPECT_EQ(env1.Message()->Signature(), complaintMsg.Signature());
    EXPECT_EQ(std::dynamic_pointer_cast<ComplaintsMessage>(env1.Message()) -> Complaints(), complaintMsg.Complaints());
}