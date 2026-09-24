#pragma once
#include <torch/torch.h>
#include <cstddef>
#include <vector>
#include <chrono>

struct TrainResult {
    std::vector<double> update;
    double train_ms{0.0};
    double loss{0.0};
    std::size_t parameter_count{0};
};

TrainResult train_mlp_and_extract(std::size_t requested_update_size,
                                  int samples,
                                  int epochs,
                                  uint64_t seed);

TrainResult train_cnn_and_extract(std::size_t requested_update_size,
                                  int samples,
                                  int epochs,
                                  uint64_t seed);
