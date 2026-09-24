#include "ml_models.h"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <iostream>

namespace {
struct MLPImpl : torch::nn::Module {
    torch::nn::Linear fc1{nullptr}, fc2{nullptr}, fc3{nullptr};
    MLPImpl() {
        fc1 = register_module("fc1", torch::nn::Linear(16, 32));
        fc2 = register_module("fc2", torch::nn::Linear(32, 16));
        fc3 = register_module("fc3", torch::nn::Linear(16, 2));
    }
    torch::Tensor forward(torch::Tensor x) {
        x = torch::relu(fc1->forward(x));
        x = torch::relu(fc2->forward(x));
        return fc3->forward(x);
    }
};
TORCH_MODULE(MLP);

struct CNNImpl : torch::nn::Module {
    torch::nn::Conv2d conv1{nullptr};
    torch::nn::Linear fc1{nullptr};
    CNNImpl() {
        conv1 = register_module("conv1", torch::nn::Conv2d(
            torch::nn::Conv2dOptions(1, 4, 3).stride(1).padding(1)));
        fc1 = register_module("fc1", torch::nn::Linear(4 * 8 * 8, 2));
    }
    torch::Tensor forward(torch::Tensor x) {
        x = torch::relu(conv1->forward(x));
        x = x.view({x.size(0), -1});
        return fc1->forward(x);
    }
};
TORCH_MODULE(CNN);

std::vector<double> flatten_parameters(const std::vector<torch::Tensor>& params) {
    std::vector<double> out;
    for (const auto& p : params) {
        auto cpu = p.detach().to(torch::kCPU).contiguous().view(-1);
        auto accessor = cpu.accessor<float, 1>();
        for (int64_t i = 0; i < cpu.numel(); ++i) out.push_back(static_cast<double>(accessor[i]));
    }
    return out;
}

std::vector<double> resize_update(std::vector<double> v, std::size_t n) {
    if (v.empty()) return std::vector<double>(n, 0.0);
    std::vector<double> out(n);
    for (std::size_t i = 0; i < n; ++i) out[i] = v[i % v.size()];
    return out;
}
}

TrainResult train_mlp_and_extract(std::size_t n, int samples, int epochs, uint64_t seed) {
    torch::manual_seed(seed);
    MLP model;
    model->train();
    torch::optim::SGD opt(model->parameters(), torch::optim::SGDOptions(0.05));
    auto x = torch::randn({samples, 16});
    auto y = (x.sum(1) > 0).to(torch::kLong);
    auto start = std::chrono::steady_clock::now();
    double loss_value = 0.0;
    for (int e = 0; e < epochs; ++e) {
        auto pred = model->forward(x);
        auto loss = torch::nn::functional::cross_entropy(pred, y);
        opt.zero_grad();
        loss.backward();
        opt.step();
        loss_value = loss.item<double>();
    }
    auto end = std::chrono::steady_clock::now();
    auto raw = flatten_parameters(model->parameters());
    TrainResult r;
    r.update = resize_update(std::move(raw), n);
    r.train_ms = std::chrono::duration<double, std::milli>(end - start).count();
    r.loss = loss_value;
    r.parameter_count = 0;
    for (const auto& p : model->parameters()) r.parameter_count += p.numel();
    return r;
}

TrainResult train_cnn_and_extract(std::size_t n, int samples, int epochs, uint64_t seed) {
    torch::manual_seed(seed);
    CNN model;
    model->train();
    torch::optim::SGD opt(model->parameters(), torch::optim::SGDOptions(0.02));
    auto x = torch::randn({samples, 1, 8, 8});
    auto y = (x.mean({1,2,3}) > 0).to(torch::kLong);
    auto start = std::chrono::steady_clock::now();
    double loss_value = 0.0;
    for (int e = 0; e < epochs; ++e) {
        auto pred = model->forward(x);
        auto loss = torch::nn::functional::cross_entropy(pred, y);
        opt.zero_grad();
        loss.backward();
        opt.step();
        loss_value = loss.item<double>();
    }
    auto end = std::chrono::steady_clock::now();
    auto raw = flatten_parameters(model->parameters());
    TrainResult r;
    r.update = resize_update(std::move(raw), n);
    r.train_ms = std::chrono::duration<double, std::milli>(end - start).count();
    r.loss = loss_value;
    r.parameter_count = 0;
    for (const auto& p : model->parameters()) r.parameter_count += p.numel();
    return r;
}
