#pragma once

#include "core/byte_array/const_byte_array.hpp"
#include "core/serializers/byte_array.hpp"
#include "core/serializers/byte_array_buffer.hpp"
#include "dkg/mcl_serializers.hpp"
#include "network/muddle/rpc/client.hpp"

namespace fetch {
namespace dkg {

    using DKGSerializer  = fetch::serializers::ByteArrayBuffer;

    class DKGMessage {
    public:
        using Signature = byte_array::ConstByteArray;
        using MuddleAddress  = byte_array::ConstByteArray;
        using Coefficient = mcl::bn256::G2;
        using Share = mcl::bn256::Fr;

        using CabinetId = MuddleAddress;

        enum class MessageType : uint8_t {
            COEFFICIENT,
            SHARE,
            COMPLAINT
        };

        MessageType getType() const {
            return type_;
        }
        Signature getSignature() const {
            return signature_;
        }
        virtual DKGSerializer serialize() const = 0;
    protected:
        const MessageType type_;
        Signature signature_;

        explicit DKGMessage(MessageType type): type_{type} {};
        explicit DKGMessage(MessageType type, Signature sig): type_{type}, signature_{std::move(sig)} {};
    };

    class Coefficients : public DKGMessage {
        uint8_t phase_;
        std::vector<Coefficient> coefficients_;
    public:
        explicit Coefficients(DKGSerializer &serialiser): DKGMessage{MessageType::COEFFICIENT} {
            mcl::bn256::G2 x;
            serialiser >> phase_;
            Serialize(serialiser, x);
            serialiser >> signature_;
            //serialiser >> phase_ >> coefficients_ >> signature_;
        };
        explicit Coefficients(uint8_t phase, std::vector<Coefficient> coeff, Signature sig):
            DKGMessage{MessageType::COEFFICIENT, std::move(sig)}, phase_{phase}, coefficients_{std::move(coeff)} {};
        DKGSerializer serialize() const override {
            DKGSerializer serializer;
            serializer << phase_;
            //mcl::bn256::Fr x;
            std::vector<mcl::bn256::G2> x;
            Deserialize(serializer, x);
            serializer << signature_;
            return serializer;
        }
        uint8_t getPhase() const {
            return phase_;
        }
        const std::vector<Coefficient>& getCoefficients() const {
            return coefficients_;
        }
    };

    class Shares : public DKGMessage {
        uint8_t phase_;
        std::unordered_map<CabinetId, int> null_;
        std::unordered_map<CabinetId, std::pair<Share, Share>> shares_; ///< Shares for a particular committee member
    public:
        explicit Shares(DKGSerializer &serialiser): DKGMessage{MessageType::SHARE} {
            //serialiser >> phase_ >> shares_ >> signature_;
        };
        explicit Shares(uint8_t phase, std::unordered_map<CabinetId, std::pair<Share, Share>> shares,
                Signature sig):
            DKGMessage{MessageType::SHARE, std::move(sig)}, phase_{phase}, shares_{std::move(shares)} {};
        DKGSerializer serialize() const override {
            DKGSerializer serializer;
            //serializer << phase_ << shares_ << signature_;
            return serializer;
        }
        uint8_t getPhase() const {
            return phase_;
        }
        const std::unordered_map<CabinetId, std::pair<Share, Share>>& getShares() const {
            return shares_;
        }
    };

    class Complaints : public DKGMessage {
        std::unordered_set<CabinetId> complaints_; ///< Committee members that you are complaining against
    public:
        explicit Complaints(DKGSerializer &serialiser): DKGMessage{MessageType::COMPLAINT} {
            serialiser >> complaints_ >> signature_;
        };
        explicit Complaints(std::unordered_set<CabinetId> complaints, Signature sig):
            DKGMessage{MessageType::COMPLAINT, std::move(sig)}, complaints_{std::move(complaints)} {};
        DKGSerializer  serialize() const override {
            DKGSerializer serializer;
            serializer << complaints_ << signature_;
            return serializer;
        }
        const std::unordered_set<CabinetId>& getComplaints() const {
            return complaints_;
        }
    };

    class DKGEnvelop {
        using MessageType = DKGMessage::MessageType;
        using Payload = byte_array::ConstByteArray;

    public:
        DKGEnvelop() = default;
        explicit DKGEnvelop(const DKGMessage &msg): type_{msg.getType()}, serialisedMessage_{msg.serialize().data()} {};

        template<typename T>
        void serialize(T &serialiser) const {
            serialiser << (uint8_t) type_ << serialisedMessage_;
        }

        template<typename T>
        void deserialize(T &serialiser) {
            uint8_t val;
            serialiser >> val;
            type_ = (MessageType) val;
            serialiser >> serialisedMessage_;
        }

        std::shared_ptr<DKGMessage> getMessage() const;

    private:
        MessageType type_;
        Payload serialisedMessage_;
    };

    template<typename T>
    inline void Serialize(T &serializer, DKGEnvelop const &env) {
        env.serialize(serializer);
    }

    template<typename T>
    inline void Deserialize(T &serializer, DKGEnvelop &env) {
        env.deserialize(serializer);
    }

}
}